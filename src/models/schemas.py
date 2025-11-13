"""
Pydantic models and schemas for CM-04 Scanner
"""

from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, validator


class LoginMethod(str, Enum):
    """Login method enumeration"""
    LOCAL = "local"
    DOMAIN = "domain"


class PrivilegeType(str, Enum):
    """Privilege type enumeration"""
    OWNER = "owner"
    GROUP = "group"
    SUDO = "sudo"


class JobStatus(str, Enum):
    """Job status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class HostInput(BaseModel):
    """Host input model"""
    hostname: str = Field(..., description="Hostname or IP address")
    code_paths: List[str] = Field(..., description="List of code paths to analyze")

    @validator('hostname')
    def validate_hostname(cls, v):
        if not v.strip():
            raise ValueError('Hostname cannot be empty')
        return v.strip()

    @validator('code_paths')
    def validate_code_paths(cls, v):
        if not v:
            raise ValueError('At least one code path must be provided')
        return [path.strip() for path in v if path.strip()]


class ScanRequest(BaseModel):
    """Scan request model"""
    hosts: List[HostInput] = Field(..., description="List of hosts to scan")
    job_name: Optional[str] = Field(None, description="Optional job name")
    tags: Optional[List[str]] = Field(None, description="Optional job tags")
    ssh_concurrency: Optional[int] = Field(10, ge=1, le=50, description="Number of concurrent SSH sessions (1-50)")


class AccessResult(BaseModel):
    """Access result model for a single user"""
    user_id: str = Field(..., description="User identifier")
    login_method: LoginMethod = Field(..., description="How user can log in")
    privilege_type: PrivilegeType = Field(..., description="Type of privilege granting access")
    privilege_source: str = Field(..., description="Source of privilege (group name, owner, or sudo)")
    access_method: str = Field(..., description="How user gets access (/etc/passwd or domain(group))")
    enabled: str = Field(..., description="Y if account is enabled, N if locked/disabled")


class HostScanResult(BaseModel):
    """Scan result for a single host"""
    hostname: str = Field(..., description="Hostname")
    code_path: str = Field(..., description="Code path analyzed")
    users_with_access: List[AccessResult] = Field(..., description="Users who can write to the path")
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)
    error_message: Optional[str] = Field(None, description="Error message if scan failed")


class JobResult(BaseModel):
    """Complete job result"""
    job_id: str = Field(..., description="Unique job identifier")
    job_name: Optional[str] = Field(None, description="Job name")
    status: JobStatus = Field(..., description="Current job status")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = Field(None, description="Job start time")
    completed_at: Optional[datetime] = Field(None, description="Job completion time")
    total_hosts: int = Field(..., description="Total number of hosts to scan")
    completed_hosts: int = Field(default=0, description="Number of hosts completed")
    failed_hosts: int = Field(default=0, description="Number of hosts failed")
    results: List[HostScanResult] = Field(default_factory=list, description="Scan results")
    error_message: Optional[str] = Field(None, description="Overall job error message")


class JobProgress(BaseModel):
    """Job progress update"""
    job_id: str
    status: JobStatus
    completed_hosts: int
    total_hosts: int
    current_host: Optional[str] = None
    error_message: Optional[str] = None


class SSHConnectionInfo(BaseModel):
    """SSH connection information"""
    hostname: str
    port: int = 22
    username: Optional[str] = None
    key_file: Optional[str] = None


class FileSystemPermission(BaseModel):
    """File system permission model"""
    path: str
    owner: str
    group: str
    permissions: str  # e.g., "rwxr-xr-x"
    is_directory: bool


class GroupMember(BaseModel):
    """Group member model"""
    username: str
    full_name: Optional[str] = None
    uid: Optional[int] = None


class DomainGroup(BaseModel):
    """Domain group model"""
    group_name: str
    members: List[GroupMember] = Field(default_factory=list)


class UserCapabilities(BaseModel):
    """User capabilities model"""
    username: str
    has_sudo: bool = False
    sudo_rules: List[str] = Field(default_factory=list)
    primary_group: str
    secondary_groups: List[str] = Field(default_factory=list)


class DebugLog(BaseModel):
    """Debug log entry"""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    level: str = Field(..., description="Log level (DEBUG, INFO, WARNING, ERROR)")
    hostname: Optional[str] = None
    message: str = Field(..., description="Log message")
    details: Optional[Dict[str, Any]] = None


class ApiError(BaseModel):
    """API error response"""
    error: str = Field(..., description="Error message")
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HealthCheck(BaseModel):
    """Health check response"""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="Application version")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ssh_connections_available: int = Field(..., description="Available SSH connections")
    database_connected: bool = Field(..., description="Database connection status")


class AuditSummary(BaseModel):
    """Summary of a completed audit for the audit history panel"""
    job_id: str = Field(..., description="Unique job identifier")
    job_name: Optional[str] = Field(None, description="Job name")
    run_number: str = Field(..., description="Human-readable run identifier")
    status: JobStatus = Field(..., description="Current job status")
    created_at: datetime = Field(..., description="When audit was created")
    started_at: Optional[datetime] = Field(None, description="When audit started")
    completed_at: Optional[datetime] = Field(None, description="When audit completed")
    run_duration_seconds: Optional[int] = Field(None, description="Total run time in seconds")
    total_hosts: int = Field(..., description="Number of hosts scanned")
    completed_hosts: int = Field(default=0, description="Successfully completed hosts")
    failed_hosts: int = Field(default=0, description="Failed hosts")
    is_archived: bool = Field(default=False, description="Whether audit is archived")
    parent_job_id: Optional[str] = Field(None, description="ID of previous audit if this is a rerun")
    tags: Optional[List[str]] = Field(default_factory=list, description="Job tags")


class AccessDifference(BaseModel):
    """Represents a difference in access between two audit runs"""
    hostname: str = Field(..., description="Hostname")
    code_path: str = Field(..., description="Code path")
    change_type: str = Field(..., description="Type of change: added, removed, modified")
    user_id: str = Field(..., description="User identifier")
    previous_access: Optional[AccessResult] = Field(None, description="Previous access details")
    current_access: Optional[AccessResult] = Field(None, description="Current access details")
    description: str = Field(..., description="Human-readable description of the change")


class AuditComparison(BaseModel):
    """Comparison results between two audit runs"""
    current_job_id: str = Field(..., description="Current audit job ID")
    previous_job_id: str = Field(..., description="Previous audit job ID")
    comparison_timestamp: datetime = Field(default_factory=datetime.utcnow)
    differences: List[AccessDifference] = Field(default_factory=list, description="List of differences found")
    summary: Dict[str, int] = Field(default_factory=dict, description="Summary statistics")
    has_changes: bool = Field(..., description="Whether any changes were detected")


class RerunRequest(BaseModel):
    """Request to rerun an audit"""
    job_id: str = Field(..., description="ID of the audit to rerun")
    compare_with_previous: bool = Field(default=True, description="Whether to compare with previous run")