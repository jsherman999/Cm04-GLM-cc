"""
Access Control Analyzer for CM-04 Scanner
Analyzes filesystem permissions and user access rights
"""

import asyncio
import re
import logging
from typing import List, Dict, Set, Optional, Tuple
from pathlib import Path
import pwd
import grp
import stat

from .ssh_engine import ssh_engine, SSHCommandResult, SSHConnectionInfo
from ..models.schemas import (
    FileSystemPermission,
    AccessResult,
    UserCapabilities,
    LoginMethod,
    PrivilegeType,
    GroupMember,
    DomainGroup
)


logger = logging.getLogger(__name__)


class AccessAnalyzer:
    """Analyzes access control for Linux/AIX filesystem paths"""

    def __init__(self):
        self.permission_cache: Dict[str, FileSystemPermission] = {}
        self.user_cache: Dict[str, UserCapabilities] = {}
        self.os_cache: Dict[str, str] = {}  # Cache OS type per host

    async def detect_os(self, conn_info: SSHConnectionInfo) -> str:
        """Detect OS type (Linux or AIX) for a host"""
        if conn_info.hostname in self.os_cache:
            return self.os_cache[conn_info.hostname]
        
        try:
            result = await ssh_engine.execute_command(conn_info, "uname -s")
            if result.exit_status == 0:
                os_type = result.stdout.strip()
                # Normalize to 'AIX' or 'Linux'
                if 'AIX' in os_type.upper():
                    os_type = 'AIX'
                else:
                    os_type = 'Linux'
                self.os_cache[conn_info.hostname] = os_type
                logger.info(f"Detected OS for {conn_info.hostname}: {os_type}")
                return os_type
            else:
                # Default to Linux if detection fails
                logger.warning(f"Could not detect OS for {conn_info.hostname}, defaulting to Linux")
                self.os_cache[conn_info.hostname] = 'Linux'
                return 'Linux'
        except Exception as e:
            logger.error(f"Error detecting OS for {conn_info.hostname}: {e}, defaulting to Linux")
            self.os_cache[conn_info.hostname] = 'Linux'
            return 'Linux'

    async def is_user_local(self, conn_info: SSHConnectionInfo, username: str) -> bool:
        """Check if user exists in /etc/passwd (is a local user)"""
        try:
            cmd = f"grep '^{username}:' /etc/passwd >/dev/null 2>&1 && echo 'YES' || echo 'NO'"
            result = await ssh_engine.execute_command(conn_info, cmd)
            is_local = result.stdout.strip() == 'YES'
            logger.debug(f"User {username} on {conn_info.hostname}: local={is_local}")
            return is_local
        except Exception as e:
            logger.error(f"Error checking if {username} is local on {conn_info.hostname}: {e}")
            return False

    async def is_account_enabled(self, conn_info: SSHConnectionInfo, username: str) -> bool:
        """Check if user account is enabled (not locked, has valid shell)"""
        try:
            os_type = await self.detect_os(conn_info)
            
            if os_type == 'AIX':
                # AIX: Check account status with lsuser
                cmd = f"lsuser -a account_locked shell {username} 2>/dev/null"
                result = await ssh_engine.execute_command(conn_info, cmd)
                if result.exit_status != 0:
                    return False
                
                output = result.stdout.strip()
                # Parse output like: "username account_locked=false shell=/bin/ksh"
                is_locked = 'account_locked=true' in output.lower()
                has_valid_shell = any(shell in output for shell in ['bash', 'sh', 'ksh', 'zsh', 'csh', 'tcsh'])
                has_nologin = 'nologin' in output.lower() or 'false' in output.lower()
                
                return not is_locked and has_valid_shell and not has_nologin
            else:
                # Linux: Check passwd -S for lock status and /etc/passwd for shell
                cmd = f"""
                # Check if account is locked
                LOCK_STATUS=$(passwd -S {username} 2>/dev/null | awk '{{print $2}}')
                # Get shell from /etc/passwd
                SHELL=$(getent passwd {username} 2>/dev/null | cut -d: -f7)
                echo "$LOCK_STATUS|$SHELL"
                """
                result = await ssh_engine.execute_command(conn_info, cmd)
                if result.exit_status != 0:
                    return False
                
                output = result.stdout.strip()
                if '|' not in output:
                    return False
                
                lock_status, shell = output.split('|', 1)
                
                # P = Password set (unlocked), L = Locked, NP = No password
                is_locked = lock_status.strip() in ['L', 'LK']
                has_valid_shell = any(s in shell for s in ['bash', 'sh', 'ksh', 'zsh', 'csh', 'tcsh'])
                has_nologin = 'nologin' in shell.lower() or 'false' in shell.lower()
                
                return not is_locked and has_valid_shell and not has_nologin
                
        except Exception as e:
            logger.error(f"Error checking if {username} is enabled on {conn_info.hostname}: {e}")
            return False

    async def get_domain_info(self, conn_info: SSHConnectionInfo) -> Optional[str]:
        """Get the domain name the host is joined to (if any)"""
        try:
            # Try vastool first
            cmd = "vastool info domain 2>/dev/null || echo 'NONE'"
            result = await ssh_engine.execute_command(conn_info, cmd)
            if result.exit_status == 0 and result.stdout.strip() not in ['NONE', '']:
                domain = result.stdout.strip()
                logger.debug(f"Host {conn_info.hostname} joined to domain: {domain}")
                return domain
            
            # Try realm for systemd-based systems
            cmd = "realm list 2>/dev/null | grep 'domain-name:' | awk '{print $2}' | head -1 || echo 'NONE'"
            result = await ssh_engine.execute_command(conn_info, cmd)
            if result.exit_status == 0 and result.stdout.strip() not in ['NONE', '']:
                domain = result.stdout.strip()
                logger.debug(f"Host {conn_info.hostname} joined to domain: {domain}")
                return domain
            
            return None
        except Exception as e:
            logger.error(f"Error getting domain info for {conn_info.hostname}: {e}")
            return None

    async def analyze_path_access(self, conn_info: SSHConnectionInfo, code_path: str) -> List[AccessResult]:
        """
        Analyze who can write to a given code path on a remote host
        Returns list of users with write access and how they got it
        """
        hostname = conn_info.hostname
        logger.info(f"Analyzing access to {code_path} on {hostname}")

        try:
            # Get filesystem permissions for the path
            fs_perm = await self.get_filesystem_permissions(conn_info, code_path)
            if not fs_perm:
                logger.error(f"Could not get permissions for {code_path} on {hostname}")
                return []

            # Get all users who can log into the system
            login_users = await self.get_login_users(conn_info)

            # Check access for each user
            access_results = []
            for user in login_users:
                user_access = await self.check_user_path_access(conn_info, user, fs_perm)
                if user_access:
                    access_results.extend(user_access)

            logger.info(f"Found {len(access_results)} users with write access to {code_path} on {hostname}")
            return access_results

        except Exception as e:
            logger.error(f"Error analyzing access to {code_path} on {hostname}: {e}")
            return []

    async def get_filesystem_permissions(self, conn_info: SSHConnectionInfo, path: str) -> Optional[FileSystemPermission]:
        """Get filesystem permissions for a path"""
        cache_key = f"{conn_info.hostname}:{path}"

        if cache_key in self.permission_cache:
            return self.permission_cache[cache_key]

        try:
            # Use ls -ld for maximum portability across Unix/Linux/AIX
            # Get both numeric and named versions to ensure we get the data
            combined_cmd = f"""
            # Get file info with names (ls -ld) and numeric (ls -ldn)
            LS_OUTPUT=$(ls -ld '{path}' 2>/dev/null) || exit 1
            echo "$LS_OUTPUT"
            
            # Also get numeric version for backup
            echo "---NUMERIC---"
            ls -ldn '{path}' 2>/dev/null || echo "FAILED"
            """
            
            result = await ssh_engine.execute_command(conn_info, combined_cmd)

            if result.exit_status != 0:
                logger.warning(f"Path {path} not found on {conn_info.hostname}")
                return None

            # Parse the output
            output_lines = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            
            logger.debug(f"Command output for {path} on {conn_info.hostname}: {output_lines}")
            
            if len(output_lines) < 1:
                logger.error(f"Empty command output for {path} on {conn_info.hostname}")
                return None
            
            # First line is ls -ld output with names
            ls_output = output_lines[0]
            parts = ls_output.split()
            if len(parts) < 4:
                logger.error(f"Unexpected ls output for {path} on {conn_info.hostname}: {ls_output}")
                return None

            permissions_str = parts[0]  # e.g., drwxr-xr-x
            owner = parts[2]  # Owner name or UID
            group = parts[3]  # Group name or GID
            
            logger.debug(f"Parsed from ls -ld: owner={owner}, group={group}, permissions={permissions_str}")
            
            # If we got numeric IDs instead of names, that's still valid
            # The scanner will handle numeric IDs appropriately
            if not owner or not group:
                logger.error(f"Failed to parse owner/group for {path} on {conn_info.hostname}. Output: {ls_output}")
                return None
            
            # Determine if it's a directory
            is_directory = permissions_str.startswith('d')

            # Convert permissions string to rwx format (skip first char which is file type)
            rwx_perm = permissions_str[1:] if len(permissions_str) > 1 else "---------"

            fs_perm = FileSystemPermission(
                path=path,
                owner=owner,
                group=group,
                permissions=rwx_perm,
                is_directory=is_directory
            )

            self.permission_cache[cache_key] = fs_perm
            return fs_perm

        except Exception as e:
            logger.error(f"Error getting filesystem permissions for {path} on {conn_info.hostname}: {e}")
            return None

    async def get_login_users(self, conn_info: SSHConnectionInfo) -> List[str]:
        """Get list of users who can log into the system"""
        try:
            os_type = await self.detect_os(conn_info)
            
            if os_type == 'AIX':
                # AIX: Use lsuser to get all users, filter by valid shells
                cmd = """
                lsuser -a shell home ALL 2>/dev/null | awk -F' ' '
                NR > 1 {
                    user=$1
                    for(i=2; i<=NF; i++) {
                        if($i ~ /^shell=/) {
                            split($i, s, "=")
                            shell=s[2]
                        }
                        if($i ~ /^home=/) {
                            split($i, h, "=")
                            home=h[2]
                        }
                    }
                    # Check for valid login shells
                    if (shell ~ /bash|sh|ksh|zsh|csh|tcsh/ && shell !~ /false|nologin/) {
                        print user
                    }
                }' | sort -u
                """
            else:
                # Linux: Use getent or /etc/passwd
                cmd = """
                getent passwd 2>/dev/null || cat /etc/passwd | while IFS=: read user x uid gid gecos home shell; do
                    # Check if shell is not empty and not a nologin/false shell
                    case "$shell" in
                        *bash|*sh|*ksh|*zsh|*csh|*tcsh)
                            # Check if home directory exists
                            if [ -d "$home" ]; then
                                echo "$user"
                            fi
                            ;;
                        *)
                            # Skip users with nologin, false, or empty shells
                            ;;
                    esac
                done | sort -u
                """

            result = await ssh_engine.execute_command(conn_info, cmd)

            if result.exit_status == 0:
                users = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                logger.debug(f"Found {len(users)} login users on {conn_info.hostname} ({os_type})")
                return users
            else:
                logger.error(f"Failed to get login users on {conn_info.hostname}: {result.stderr}")
                return []

        except Exception as e:
            logger.error(f"Error getting login users on {conn_info.hostname}: {e}")
            return []

    async def check_user_path_access(self, conn_info: SSHConnectionInfo, username: str, fs_perm: FileSystemPermission) -> List[AccessResult]:
        """Check if a specific user has write access to a path"""
        hostname = conn_info.hostname
        access_results = []

        try:
            # Determine login method and access method
            is_local = await self.is_user_local(conn_info, username)
            is_enabled = await self.is_account_enabled(conn_info, username)
            login_method = LoginMethod.LOCAL if is_local else LoginMethod.DOMAIN
            enabled_status = "Y" if is_enabled else "N"
            
            # Get domain info if not local
            domain_name = None
            if not is_local:
                domain_name = await self.get_domain_info(conn_info)
            
            # Check if user is owner
            if fs_perm.owner == username:
                if self._check_owner_write_permission(fs_perm.permissions):
                    access_method = "/etc/passwd" if is_local else (f"{domain_name}(owner)" if domain_name else "domain(owner)")
                    access_results.append(AccessResult(
                        user_id=username,
                        login_method=login_method,
                        privilege_type=PrivilegeType.OWNER,
                        privilege_source="owner",
                        access_method=access_method,
                        enabled=enabled_status
                    ))
                    logger.debug(f"User {username} has owner write access to {fs_perm.path} on {hostname}")
                return access_results

            # Get user capabilities
            user_caps = await self.get_user_capabilities(conn_info, username)
            if not user_caps:
                return access_results

            # Check sudo access
            if user_caps.has_sudo:
                access_method = "/etc/passwd" if is_local else (f"{domain_name}(sudo)" if domain_name else "domain(sudo)")
                access_results.append(AccessResult(
                    user_id=username,
                    login_method=login_method,
                    privilege_type=PrivilegeType.SUDO,
                    privilege_source="sudo",
                    access_method=access_method,
                    enabled=enabled_status
                ))
                logger.debug(f"User {username} has sudo access to {fs_perm.path} on {hostname}")

            # Check group access
            user_groups = user_caps.secondary_groups + [user_caps.primary_group]
            for group in user_groups:
                if group == fs_perm.group:
                    if self._check_group_write_permission(fs_perm.permissions):
                        access_method = "/etc/passwd" if is_local else (f"{domain_name}({group})" if domain_name else f"domain({group})")
                        access_results.append(AccessResult(
                            user_id=username,
                            login_method=login_method,
                            privilege_type=PrivilegeType.GROUP,
                            privilege_source=group,
                            access_method=access_method,
                            enabled=enabled_status
                        ))
                        logger.debug(f"User {username} has group write access via {group} to {fs_perm.path} on {hostname}")
                        break

            return access_results

        except Exception as e:
            logger.error(f"Error checking access for user {username} on {hostname}: {e}")
            return []

    async def get_user_capabilities(self, conn_info: SSHConnectionInfo, username: str) -> Optional[UserCapabilities]:
        """Get user capabilities including sudo and group memberships"""
        cache_key = f"{conn_info.hostname}:{username}"

        if cache_key in self.user_cache:
            return self.user_cache[cache_key]

        try:
            os_type = await self.detect_os(conn_info)
            
            # The 'id' command works on both Linux and AIX
            # id -gn: primary group name
            # id -Gn: all group names (includes primary + secondary, and domain groups on joined systems)
            commands = [
                (conn_info, f"id -gn {username} 2>/dev/null || echo 'ERROR'"),  # Primary group
                (conn_info, f"id -Gn {username} 2>/dev/null || echo 'ERROR'"),  # All groups (includes domain groups)
                (conn_info, f"sudo -n -l -U {username} 2>/dev/null || echo 'NO_SUDO'"),  # Sudo rights
            ]

            results = await ssh_engine.execute_commands_parallel(commands)

            if results[0].exit_status != 0 or results[0].stdout.strip() == 'ERROR':
                logger.error(f"Could not get primary group for user {username} on {conn_info.hostname}")
                return None

            primary_group = results[0].stdout.strip()

            # Parse groups (remove primary group to avoid duplicates)
            # The 'id -Gn' command returns all groups including domain groups on joined systems
            all_groups_output = results[1].stdout.strip()
            if all_groups_output == 'ERROR':
                logger.error(f"Could not get groups for user {username} on {conn_info.hostname}")
                all_groups = [primary_group]
                secondary_groups = []
            else:
                all_groups = [g.strip() for g in all_groups_output.split() if g.strip()]
                secondary_groups = [g for g in all_groups if g != primary_group]
            
            logger.debug(f"User {username} on {conn_info.hostname} ({os_type}): primary={primary_group}, all_groups={all_groups}")

            # Check sudo access
            sudo_output = results[2].stdout.strip()
            has_sudo = sudo_output != "NO_SUDO" and results[2].exit_status == 0
            sudo_rules = []
            if has_sudo:
                sudo_rules = [line.strip() for line in sudo_output.split('\n') if line.strip()]

            user_caps = UserCapabilities(
                username=username,
                has_sudo=has_sudo,
                sudo_rules=sudo_rules,
                primary_group=primary_group,
                secondary_groups=secondary_groups
            )

            self.user_cache[cache_key] = user_caps
            return user_caps

        except Exception as e:
            logger.error(f"Error getting capabilities for user {username} on {conn_info.hostname}: {e}")
            return None

    def _octal_to_rwx(self, octal_perm: str) -> str:
        """Convert octal permission string to rwx format"""
        try:
            perm_int = int(octal_perm, 8)

            rwx = ""
            # Owner permissions
            rwx += "r" if perm_int & 0o400 else "-"
            rwx += "w" if perm_int & 0o200 else "-"
            rwx += "x" if perm_int & 0o100 else "-"

            # Group permissions
            rwx += "r" if perm_int & 0o040 else "-"
            rwx += "w" if perm_int & 0o020 else "-"
            rwx += "x" if perm_int & 0o010 else "-"

            # Other permissions
            rwx += "r" if perm_int & 0o004 else "-"
            rwx += "w" if perm_int & 0o002 else "-"
            rwx += "x" if perm_int & 0o001 else "-"

            return rwx
        except ValueError:
            return "---------"

    def _check_owner_write_permission(self, permissions: str) -> bool:
        """Check if owner has write permission"""
        return len(permissions) >= 2 and permissions[1] == 'w'

    def _check_group_write_permission(self, permissions: str) -> bool:
        """Check if group has write permission"""
        return len(permissions) >= 5 and permissions[4] == 'w'

    def _check_other_write_permission(self, permissions: str) -> bool:
        """Check if others have write permission"""
        return len(permissions) >= 8 and permissions[7] == 'w'

    async def analyze_path_via_vastool(self, conn_info: SSHConnectionInfo, code_path: str) -> List[AccessResult]:
        """
        Analyze path access using QAS/VAS vastool for AD integration
        This extends the basic analysis with domain group information
        """
        try:
            # Get basic filesystem permissions first
            fs_perm = await self.get_filesystem_permissions(conn_info, code_path)
            if not fs_perm:
                return []

            # Get domain info
            domain_name = await self.get_domain_info(conn_info)

            # Get ACL information using vastool
            acl_groups = await self.get_vastool_acl_groups(conn_info, code_path)

            access_results = []

            # For each ACL group, get its members
            for group_name in acl_groups:
                group_members = await self.get_vastool_group_members(conn_info, group_name)

                for member in group_members:
                    # Check if domain user account is enabled
                    is_enabled = await self.is_account_enabled(conn_info, member.username)
                    enabled_status = "Y" if is_enabled else "N"
                    access_method = f"{domain_name}({group_name})" if domain_name else f"domain({group_name})"
                    
                    access_results.append(AccessResult(
                        user_id=member.username,
                        login_method=LoginMethod.DOMAIN,
                        privilege_type=PrivilegeType.GROUP,
                        privilege_source=group_name,
                        access_method=access_method,
                        enabled=enabled_status
                    ))

            # Also get local users with access
            local_access = await self.analyze_path_access(conn_info, code_path)
            access_results.extend(local_access)

            # Remove duplicates
            unique_results = []
            seen = set()
            for result in access_results:
                key = (result.user_id, result.login_method, result.privilege_type, result.privilege_source)
                if key not in seen:
                    seen.add(key)
                    unique_results.append(result)

            return unique_results

        except Exception as e:
            logger.error(f"Error analyzing path via vastool for {code_path} on {conn_info.hostname}: {e}")
            return []

    async def get_vastool_acl_groups(self, conn_info: SSHConnectionInfo, path: str) -> List[str]:
        """Get groups with ACL access using vastool"""
        try:
            from ..config.settings import settings

            cmd = f"{settings.vastool_path} info acl '{path}' 2>/dev/null"
            result = await ssh_engine.execute_command(conn_info, cmd)

            if result.exit_status != 0:
                logger.warning(f"vastool info acl failed for {path} on {conn_info.hostname}")
                return []

            # Parse vastool output for group names
            groups = []
            for line in result.stdout.split('\n'):
                if 'group:' in line.lower():
                    # Extract group name (format varies by vastool version)
                    match = re.search(r'group:\s*(\w+)', line, re.IGNORECASE)
                    if match:
                        groups.append(match.group(1))

            logger.debug(f"Found {len(groups)} ACL groups for {path} on {conn_info.hostname}")
            return groups

        except Exception as e:
            logger.error(f"Error getting vastool ACL groups for {path} on {conn_info.hostname}: {e}")
            return []

    async def get_vastool_group_members(self, conn_info: SSHConnectionInfo, group_name: str) -> List[GroupMember]:
        """Get group members using vastool"""
        cache_key = f"{conn_info.hostname}:group:{group_name}"

        if cache_key in self.group_cache:
            return self.group_cache[cache_key].members

        try:
            from ..config.settings import settings

            cmd = f"{settings.vastool_path} -u host group list '{group_name}' 2>/dev/null"
            result = await ssh_engine.execute_command(conn_info, cmd)

            if result.exit_status != 0:
                logger.warning(f"vastool group list failed for {group_name} on {conn_info.hostname}")
                return []

            members = []
            for line in result.stdout.split('\n'):
                username = line.strip()
                if username:
                    members.append(GroupMember(username=username))

            # Cache the result
            domain_group = DomainGroup(group_name=group_name, members=members)
            self.group_cache[cache_key] = domain_group

            logger.debug(f"Found {len(members)} members in group {group_name} on {conn_info.hostname}")
            return members

        except Exception as e:
            logger.error(f"Error getting vastool group members for {group_name} on {conn_info.hostname}: {e}")
            return []

    def clear_cache(self):
        """Clear all caches"""
        self.permission_cache.clear()
        self.user_cache.clear()
        self.group_cache.clear()
        logger.info("Access analyzer caches cleared")


# Global access analyzer instance
access_analyzer = AccessAnalyzer()