"""
Enhanced logging utilities for CM-04 Scanner
"""

import logging
import logging.handlers
import sys
import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import traceback

from ..config.settings import settings


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""

    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }

        # Add extra fields
        if hasattr(record, 'hostname'):
            log_data['hostname'] = record.hostname
        if hasattr(record, 'job_id'):
            log_data['job_id'] = record.job_id
        if hasattr(record, 'user_id'):
            log_data['user_id'] = record.user_id
        if hasattr(record, 'duration'):
            log_data['duration'] = record.duration
        if hasattr(record, 'extra'):
            log_data.update(record.extra)

        return json.dumps(log_data)


class ContextFilter(logging.Filter):
    """Filter to add context information to log records"""

    def __init__(self):
        super().__init__()
        self.context = {}

    def filter(self, record):
        # Add context to record
        for key, value in self.context.items():
            setattr(record, key, value)
        return True

    def set_context(self, **kwargs):
        """Set context variables"""
        self.context.update(kwargs)

    def clear_context(self):
        """Clear context variables"""
        self.context.clear()


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output"""

    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }

    def format(self, record):
        if settings.debug:
            # Use colored output in debug mode
            color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
            reset = self.COLORS['RESET']

            # Format: [LEVEL] [TIMESTAMP] [MODULE] MESSAGE
            formatted = (
                f"{color}[{record.levelname}]{reset} "
                f"[{datetime.fromtimestamp(record.created).strftime('%H:%M:%S')}] "
                f"[{record.module}] {record.getMessage()}"
            )

            if record.exc_info:
                formatted += f"\n{self.formatException(record.exc_info)}"

            return formatted
        else:
            # Production format
            return (
                f"[{record.levelname}] "
                f"{datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')} "
                f"{record.name}: {record.getMessage()}"
            )


def setup_logging():
    """Setup comprehensive logging for the application"""
    # Create logs directory
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if settings.debug else logging.INFO)

    # Clear existing handlers
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if settings.debug else logging.INFO)
    console_handler.setFormatter(ColoredFormatter())
    root_logger.addHandler(console_handler)

    # File handler for general logs
    file_handler = logging.handlers.RotatingFileHandler(
        logs_dir / "cm04_scanner.log",
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(JSONFormatter())
    root_logger.addHandler(file_handler)

    # Error file handler
    error_handler = logging.handlers.RotatingFileHandler(
        logs_dir / "cm04_scanner_errors.log",
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(JSONFormatter())
    root_logger.addHandler(error_handler)

    # SSH operation logs
    ssh_handler = logging.handlers.RotatingFileHandler(
        logs_dir / "ssh_operations.log",
        maxBytes=50 * 1024 * 1024,  # 50MB
        backupCount=10
    )
    ssh_handler.setLevel(logging.DEBUG)
    ssh_handler.setFormatter(JSONFormatter())
    ssh_logger = logging.getLogger("ssh_engine")
    ssh_logger.addHandler(ssh_handler)
    ssh_logger.propagate = False  # Don't propagate to root logger

    # Access analysis logs
    access_handler = logging.handlers.RotatingFileHandler(
        logs_dir / "access_analysis.log",
        maxBytes=20 * 1024 * 1024,  # 20MB
        backupCount=5
    )
    access_handler.setLevel(logging.DEBUG)
    access_handler.setFormatter(JSONFormatter())
    access_logger = logging.getLogger("access_analyzer")
    access_logger.addHandler(access_handler)
    access_logger.propagate = False  # Don't propagate to root logger

    # API request logs
    api_handler = logging.handlers.RotatingFileHandler(
        logs_dir / "api_requests.log",
        maxBytes=20 * 1024 * 1024,  # 20MB
        backupCount=5
    )
    api_handler.setLevel(logging.INFO)
    api_handler.setFormatter(JSONFormatter())
    api_logger = logging.getLogger("api")
    api_logger.addHandler(api_handler)
    api_logger.propagate = False  # Don't propagate to root logger

    # Reduce noise from third-party libraries
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("fastapi").setLevel(logging.WARNING)
    logging.getLogger("uvicorn").setLevel(logging.WARNING)

    return root_logger


# Context filter for global use
context_filter = ContextFilter()


def get_logger(name: str) -> logging.Logger:
    """Get a logger with context filter attached"""
    logger = logging.getLogger(name)
    if not any(isinstance(f, ContextFilter) for f in logger.filters):
        logger.addFilter(context_filter)
    return logger


def set_log_context(**kwargs):
    """Set global logging context"""
    context_filter.set_context(**kwargs)


def clear_log_context():
    """Clear global logging context"""
    context_filter.clear_context()


class LogContext:
    """Context manager for temporary log context"""

    def __init__(self, **kwargs):
        self.context = kwargs
        self.previous_context = {}

    def __enter__(self):
        # Store previous context and set new context
        self.previous_context = context_filter.context.copy()
        context_filter.set_context(**self.context)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore previous context
        context_filter.clear_context()
        context_filter.set_context(**self.previous_context)


def log_function_call(func):
    """Decorator to log function calls"""
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        func_name = f"{func.__module__}.{func.__name__}"

        start_time = datetime.utcnow()
        logger.debug(f"Calling {func_name}", extra={
            'function': func_name,
            'args_count': len(args),
            'kwargs_keys': list(kwargs.keys())
        })

        try:
            result = func(*args, **kwargs)
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.debug(f"Completed {func_name}", extra={
                'function': func_name,
                'duration': duration,
                'success': True
            })
            return result

        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.error(f"Failed {func_name}: {e}", extra={
                'function': func_name,
                'duration': duration,
                'success': False,
                'error': str(e)
            })
            raise

    return wrapper


def log_ssh_operation(hostname: str, operation: str, duration: Optional[float] = None,
                     success: bool = True, error: Optional[str] = None):
    """Log SSH operations"""
    logger = logging.getLogger("ssh_engine")
    extra = {
        'hostname': hostname,
        'operation': operation,
        'success': success
    }

    if duration is not None:
        extra['duration'] = duration

    if error:
        extra['error'] = error

    if success:
        logger.info(f"SSH {operation} completed for {hostname}", extra=extra)
    else:
        logger.error(f"SSH {operation} failed for {hostname}: {error}", extra=extra)


def log_access_analysis(hostname: str, path: str, user_count: int,
                       duration: Optional[float] = None, error: Optional[str] = None):
    """Log access analysis operations"""
    logger = logging.getLogger("access_analyzer")
    extra = {
        'hostname': hostname,
        'path': path,
        'user_count': user_count
    }

    if duration is not None:
        extra['duration'] = duration

    if error:
        extra['error'] = error
        logger.error(f"Access analysis failed for {hostname}:{path}: {error}", extra=extra)
    else:
        logger.info(f"Access analysis completed for {hostname}:{path}, {user_count} users", extra=extra)


def log_api_request(method: str, path: str, status_code: int, duration: float,
                   user_id: Optional[str] = None, job_id: Optional[str] = None):
    """Log API requests"""
    logger = logging.getLogger("api")
    extra = {
        'method': method,
        'path': path,
        'status_code': status_code,
        'duration': duration
    }

    if user_id:
        extra['user_id'] = user_id

    if job_id:
        extra['job_id'] = job_id

    level = logging.INFO if status_code < 400 else logging.ERROR
    logger.log(level, f"{method} {path} - {status_code}", extra=extra)


class AuditLogger:
    """Specialized logger for audit events"""

    def __init__(self):
        self.logger = get_logger("audit")
        # Ensure audit logs go to a separate file
        audit_handler = logging.handlers.RotatingFileHandler(
            Path("logs") / "audit.log",
            maxBytes=100 * 1024 * 1024,  # 100MB
            backupCount=20
        )
        audit_handler.setLevel(logging.INFO)
        audit_handler.setFormatter(JSONFormatter())
        audit_handler.addFilter(context_filter)
        self.logger.addHandler(audit_handler)
        self.logger.propagate = False

    def log_scan_submission(self, job_id: str, hostname_count: int, user_id: Optional[str] = None):
        """Log scan job submission"""
        self.logger.info("Scan job submitted", extra={
            'event_type': 'scan_submission',
            'job_id': job_id,
            'hostname_count': hostname_count,
            'user_id': user_id
        })

    def log_scan_completion(self, job_id: str, hosts_completed: int, hosts_failed: int):
        """Log scan job completion"""
        self.logger.info("Scan job completed", extra={
            'event_type': 'scan_completion',
            'job_id': job_id,
            'hosts_completed': hosts_completed,
            'hosts_failed': hosts_failed
        })

    def log_access_granted(self, hostname: str, user_id: str, path: str, privilege_type: str):
        """Log access rights discovery"""
        self.logger.info("Access rights discovered", extra={
            'event_type': 'access_discovered',
            'hostname': hostname,
            'user_id': user_id,
            'path': path,
            'privilege_type': privilege_type
        })

    def log_file_download(self, job_id: str, file_type: str, user_id: Optional[str] = None):
        """Log report download"""
        self.logger.info("Report downloaded", extra={
            'event_type': 'file_download',
            'job_id': job_id,
            'file_type': file_type,
            'user_id': user_id
        })


# Global audit logger instance
audit_logger = AuditLogger()


# Initialize logging when module is imported
setup_logging()