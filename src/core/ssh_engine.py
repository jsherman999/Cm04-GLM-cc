"""
SSH Engine for CM-04 Scanner with AsyncSSH multiplexing
Handles concurrent SSH connections and command execution
"""

import asyncio
import asyncssh
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path
import json
import time

from ..config.settings import settings
from ..models.schemas import SSHConnectionInfo, DebugLog


logger = logging.getLogger(__name__)


@dataclass
class SSHCommandResult:
    """Result of SSH command execution"""
    stdout: str
    stderr: str
    exit_status: int
    execution_time: float


class SSHConnectionPool:
    """Manages SSH connection pooling and reuse"""

    def __init__(self, max_connections: int = 100):
        self.max_connections = max_connections
        self.connections: Dict[str, asyncssh.SSHClientConnection] = {}
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._connection_lock: Optional[asyncio.Lock] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _ensure_loop_resources(self):
        """Ensure semaphore and lock are bound to current event loop"""
        current_loop = asyncio.get_event_loop()
        
        # If loop changed or resources not initialized, recreate them
        if self._loop != current_loop or self._semaphore is None:
            self._loop = current_loop
            self._semaphore = asyncio.Semaphore(self.max_connections)
            self._connection_lock = asyncio.Lock()
            logger.debug(f"Initialized connection pool resources for event loop {id(current_loop)}")

    @property
    def semaphore(self) -> asyncio.Semaphore:
        """Get semaphore bound to current event loop"""
        self._ensure_loop_resources()
        return self._semaphore

    @property
    def connection_lock(self) -> asyncio.Lock:
        """Get lock bound to current event loop"""
        self._ensure_loop_resources()
        return self._connection_lock

    async def get_connection(self, conn_info: SSHConnectionInfo) -> asyncssh.SSHClientConnection:
        """Get or create SSH connection"""
        async with self.semaphore:
            connection_key = self._get_connection_key(conn_info)

            async with self.connection_lock:
                # Check if connection exists and is healthy
                if connection_key in self.connections:
                    conn = self.connections[connection_key]
                    try:
                        # Test connection with simple command
                        await conn.run("true", timeout=5)
                        logger.debug(f"Reusing existing SSH connection to {connection_key}")
                        return conn
                    except (asyncssh.BrokenConnectionError, asyncssh.TimeoutError):
                        # Connection is broken, remove it
                        del self.connections[connection_key]
                        logger.info(f"Removed broken connection to {connection_key}")

                # Create new connection
                logger.info(f"Creating new SSH connection to {connection_key}")
                conn = await self._create_connection(conn_info)
                self.connections[connection_key] = conn
                return conn

    def _get_connection_key(self, conn_info: SSHConnectionInfo) -> str:
        """Generate unique connection key"""
        return f"{conn_info.username}@{conn_info.hostname}:{conn_info.port}"

    async def _create_connection(self, conn_info: SSHConnectionInfo) -> asyncssh.SSHClientConnection:
        """Create new SSH connection"""
        connect_kwargs = {
            'host': conn_info.hostname,
            'port': conn_info.port,
            'connect_timeout': settings.ssh_timeout,
            'known_hosts': None,  # Disable host key checking for internal tool
        }

        if conn_info.username:
            connect_kwargs['username'] = conn_info.username

        if conn_info.key_file:
            connect_kwargs['client_keys'] = [conn_info.key_file]
        elif settings.ssh_key_file and settings.ssh_key_file.exists():
            connect_kwargs['client_keys'] = [str(settings.ssh_key_file)]

        try:
            connection = await asyncssh.connect(**connect_kwargs)
            return connection
        except Exception as e:
            logger.error(f"Failed to connect to {conn_info.hostname}: {e}")
            raise

    async def close_connection(self, conn_info: SSHConnectionInfo):
        """Close specific SSH connection"""
        connection_key = self._get_connection_key(conn_info)
        async with self.connection_lock:
            if connection_key in self.connections:
                conn = self.connections[connection_key]
                conn.close()
                await conn.wait_closed()
                del self.connections[connection_key]
                logger.info(f"Closed SSH connection to {connection_key}")

    async def close_all(self):
        """Close all SSH connections"""
        async with self.connection_lock:
            for conn in self.connections.values():
                conn.close()

            # Wait for all connections to close
            await asyncio.gather(
                *[conn.wait_closed() for conn in self.connections.values()],
                return_exceptions=True
            )

            self.connections.clear()
            logger.info("Closed all SSH connections")


class SSHEngine:
    """Main SSH execution engine"""

    def __init__(self):
        self.pool = SSHConnectionPool(settings.ssh_concurrency_limit)
        self.debug_logs: List[DebugLog] = []

    async def execute_command(
        self,
        conn_info: SSHConnectionInfo,
        command: str,
        timeout: Optional[int] = None,
        capture_output: bool = True
    ) -> SSHCommandResult:
        """Execute command on remote host"""
        start_time = time.time()

        try:
            conn = await self.pool.get_connection(conn_info)

            # Add debug log
            self._add_debug_log(
                "DEBUG",
                f"Executing command on {conn_info.hostname}: {command}",
                hostname=conn_info.hostname
            )

            result = await conn.run(
                command,
                timeout=timeout or settings.ssh_timeout,
                check=False  # Don't raise on non-zero exit status
            )

            execution_time = time.time() - start_time

            ssh_result = SSHCommandResult(
                stdout=result.stdout.strip() if result.stdout else "",
                stderr=result.stderr.strip() if result.stderr else "",
                exit_status=result.exit_status,
                execution_time=execution_time
            )

            # Log result
            self._add_debug_log(
                "DEBUG",
                f"Command completed on {conn_info.hostname} in {execution_time:.2f}s, exit_status: {result.exit_status}",
                hostname=conn_info.hostname,
                details={
                    "command": command,
                    "exit_status": result.exit_status,
                    "execution_time": execution_time
                }
            )

            return ssh_result

        except asyncssh.TimeoutError:
            execution_time = time.time() - start_time
            error_msg = f"Command timeout on {conn_info.hostname} after {execution_time:.2f}s: {command}"
            self._add_debug_log("ERROR", error_msg, hostname=conn_info.hostname)
            raise TimeoutError(error_msg)

        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Command failed on {conn_info.hostname}: {str(e)}"
            self._add_debug_log("ERROR", error_msg, hostname=conn_info.hostname)
            raise RuntimeError(error_msg)

    async def execute_commands_parallel(
        self,
        commands: List[Tuple[SSHConnectionInfo, str]],
        timeout: Optional[int] = None
    ) -> List[SSHCommandResult]:
        """Execute multiple commands in parallel"""
        tasks = [
            self.execute_command(conn_info, command, timeout)
            for conn_info, command in commands
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to error results
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                hostname = commands[i][0].hostname
                processed_results.append(
                    SSHCommandResult(
                        stdout="",
                        stderr=str(result),
                        exit_status=-1,
                        execution_time=0.0
                    )
                )
            else:
                processed_results.append(result)

        return processed_results

    async def test_connection(self, conn_info: SSHConnectionInfo) -> bool:
        """Test SSH connection to host"""
        try:
            result = await self.execute_command(conn_info, "echo 'connection_test'", timeout=10)
            return result.exit_status == 0 and result.stdout == "connection_test"
        except Exception:
            return False

    async def get_host_info(self, conn_info: SSHConnectionInfo) -> Dict[str, Any]:
        """Get basic host information"""
        commands = [
            (conn_info, "hostname"),
            (conn_info, "uname -a"),
            (conn_info, "whoami"),
            (conn_info, "id -un"),
        ]

        results = await self.execute_commands_parallel(commands)

        return {
            "hostname": results[0].stdout,
            "uname": results[1].stdout,
            "current_user": results[2].stdout,
            "effective_user": results[3].stdout,
            "connection_test": all(r.exit_status == 0 for r in results)
        }

    def _add_debug_log(self, level: str, message: str, hostname: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        """Add debug log entry"""
        log_entry = DebugLog(
            level=level,
            hostname=hostname,
            message=message,
            details=details
        )
        self.debug_logs.append(log_entry)

        # Also log to standard logger
        if level == "ERROR":
            logger.error(f"[{hostname}] {message}")
        elif level == "WARNING":
            logger.warning(f"[{hostname}] {message}")
        elif level == "DEBUG":
            logger.debug(f"[{hostname}] {message}")
        else:
            logger.info(f"[{hostname}] {message}")

    def get_debug_logs(self, hostname: Optional[str] = None, limit: int = 1000) -> List[DebugLog]:
        """Get debug logs with optional hostname filter"""
        logs = self.debug_logs

        if hostname:
            logs = [log for log in logs if log.hostname == hostname]

        # Return most recent logs
        return logs[-limit:]

    def clear_debug_logs(self):
        """Clear debug logs"""
        self.debug_logs.clear()

    async def cleanup(self):
        """Cleanup resources"""
        await self.pool.close_all()
        logger.info("SSH engine cleaned up")


# Global SSH engine instance
ssh_engine = SSHEngine()