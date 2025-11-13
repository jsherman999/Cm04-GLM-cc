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
    """Analyzes access control for Linux filesystem paths"""

    def __init__(self):
        self.permission_cache: Dict[str, FileSystemPermission] = {}
        self.user_cache: Dict[str, UserCapabilities] = {}
        self.group_cache: Dict[str, DomainGroup] = {}

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
            # This works consistently across all platforms
            ls_cmd = f"ls -ldn '{path}' 2>/dev/null"
            result = await ssh_engine.execute_command(conn_info, ls_cmd)

            if result.exit_status != 0:
                logger.warning(f"Path {path} not found on {conn_info.hostname}")
                return None

            # Parse ls -ld output: permissions links owner group size date time name
            # Example: drwxr-xr-x 7 210884 111 4096 Jun  3 10:14 /home/jsherma2/
            parts = result.stdout.split()
            if len(parts) < 3:
                logger.error(f"Unexpected ls output for {path} on {conn_info.hostname}: {result.stdout}")
                return None

            permissions_str = parts[0]  # e.g., drwxr-xr-x
            owner_uid = parts[2]  # numeric UID
            group_gid = parts[3]  # numeric GID
            
            # Determine if it's a directory
            is_directory = permissions_str.startswith('d')
            
            # Get the actual username and group name from UID/GID
            # Try to resolve UID to username
            id_cmd = f"id -un {owner_uid} 2>/dev/null || echo '{owner_uid}'"
            id_result = await ssh_engine.execute_command(conn_info, id_cmd)
            owner = id_result.stdout.strip()
            
            # Try to resolve GID to groupname (try getent first, fall back to /etc/group)
            grp_cmd = f"getent group {group_gid} 2>/dev/null | cut -d: -f1 || grep '^[^:]*:[^:]*:{group_gid}:' /etc/group 2>/dev/null | cut -d: -f1 || echo '{group_gid}'"
            grp_result = await ssh_engine.execute_command(conn_info, grp_cmd)
            group = grp_result.stdout.strip()

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
            # Get users with valid shells (can log in)
            # Use POSIX-compliant shell syntax for AIX compatibility
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
                logger.debug(f"Found {len(users)} login users on {conn_info.hostname}")
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
            # Check if user is owner
            if fs_perm.owner == username:
                if self._check_owner_write_permission(fs_perm.permissions):
                    access_results.append(AccessResult(
                        user_id=username,
                        login_method=LoginMethod.LOCAL,
                        privilege_type=PrivilegeType.OWNER,
                        privilege_source="owner"
                    ))
                    logger.debug(f"User {username} has owner write access to {fs_perm.path} on {hostname}")
                return access_results

            # Get user capabilities
            user_caps = await self.get_user_capabilities(conn_info, username)
            if not user_caps:
                return access_results

            # Check sudo access
            if user_caps.has_sudo:
                access_results.append(AccessResult(
                    user_id=username,
                    login_method=LoginMethod.LOCAL,
                    privilege_type=PrivilegeType.SUDO,
                    privilege_source="sudo"
                ))
                logger.debug(f"User {username} has sudo access to {fs_perm.path} on {hostname}")

            # Check group access
            user_groups = user_caps.secondary_groups + [user_caps.primary_group]
            for group in user_groups:
                if group == fs_perm.group:
                    if self._check_group_write_permission(fs_perm.permissions):
                        access_results.append(AccessResult(
                            user_id=username,
                            login_method=LoginMethod.LOCAL,
                            privilege_type=PrivilegeType.GROUP,
                            privilege_source=group
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
            commands = [
                (conn_info, f"id -gn {username}"),  # Primary group
                (conn_info, f"id -Gn {username}"),  # All groups
                (conn_info, f"sudo -n -l -U {username} 2>/dev/null || echo 'NO_SUDO'"),  # Sudo rights
            ]

            results = await ssh_engine.execute_commands_parallel(commands)

            if results[0].exit_status != 0:
                logger.error(f"Could not get primary group for user {username} on {conn_info.hostname}")
                return None

            primary_group = results[0].stdout.strip()

            # Parse groups (remove primary group to avoid duplicates)
            all_groups = [g.strip() for g in results[1].stdout.split() if g.strip()]
            secondary_groups = [g for g in all_groups if g != primary_group]

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

            # Get ACL information using vastool
            acl_groups = await self.get_vastool_acl_groups(conn_info, code_path)

            access_results = []

            # For each ACL group, get its members
            for group_name in acl_groups:
                group_members = await self.get_vastool_group_members(conn_info, group_name)

                for member in group_members:
                    access_results.append(AccessResult(
                        user_id=member.username,
                        login_method=LoginMethod.DOMAIN,
                        privilege_type=PrivilegeType.GROUP,
                        privilege_source=group_name
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