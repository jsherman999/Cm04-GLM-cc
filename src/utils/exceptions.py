"""
Custom exceptions for CM-04 Scanner
"""

from typing import Optional, Dict, Any


class CM04ScannerError(Exception):
    """Base exception for CM-04 Scanner"""

    def __init__(self, message: str, error_code: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses"""
        return {
            'error': self.message,
            'error_code': self.error_code,
            'details': self.details
        }


class SSHConnectionError(CM04ScannerError):
    """SSH connection related errors"""

    def __init__(self, hostname: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"SSH connection to {hostname} failed: {message}", "SSH_CONNECTION_ERROR", details)
        self.hostname = hostname


class SSHTimeoutError(SSHConnectionError):
    """SSH timeout errors"""

    def __init__(self, hostname: str, timeout: int, details: Optional[Dict[str, Any]] = None):
        super().__init__(hostname, f"Connection timeout after {timeout} seconds", details)
        self.timeout = timeout


class SSHAuthenticationError(SSHConnectionError):
    """SSH authentication errors"""

    def __init__(self, hostname: str, auth_method: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(hostname, f"Authentication failed using {auth_method}", details)
        self.auth_method = auth_method


class FileSystemError(CM04ScannerError):
    """Filesystem related errors"""

    def __init__(self, path: str, hostname: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"Filesystem error on {hostname} for path {path}: {message}", "FILESYSTEM_ERROR", details)
        self.path = path
        self.hostname = hostname


class PathNotFoundError(FileSystemError):
    """Path not found errors"""

    def __init__(self, path: str, hostname: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(path, hostname, "Path does not exist", details)
        self.message = f"Path {path} not found on {hostname}"


class PermissionDeniedError(FileSystemError):
    """Permission denied errors"""

    def __init__(self, path: str, hostname: str, operation: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(path, hostname, f"Permission denied for {operation}", details)
        self.operation = operation


class AccessAnalysisError(CM04ScannerError):
    """Access analysis related errors"""

    def __init__(self, hostname: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"Access analysis failed on {hostname}: {message}", "ACCESS_ANALYSIS_ERROR", details)
        self.hostname = hostname


class VASToolError(AccessAnalysisError):
    """QAS/VAS vastool related errors"""

    def __init__(self, hostname: str, command: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(hostname, f"vastool command failed: {command} - {message}", details)
        self.command = command


class GroupQueryError(VASToolError):
    """Group query errors"""

    def __init__(self, hostname: str, group_name: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(hostname, f"group list {group_name}", message, details)
        self.group_name = group_name


class JobError(CM04ScannerError):
    """Job management errors"""

    def __init__(self, job_id: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"Job {job_id}: {message}", "JOB_ERROR", details)
        self.job_id = job_id


class JobNotFoundError(JobError):
    """Job not found errors"""

    def __init__(self, job_id: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(job_id, "Job not found", details)
        self.message = f"Job {job_id} not found"


class JobStateError(JobError):
    """Job state related errors"""

    def __init__(self, job_id: str, current_state: str, requested_action: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(job_id, f"Cannot {requested_action} job in state {current_state}", details)
        self.current_state = current_state
        self.requested_action = requested_action


class ValidationError(CM04ScannerError):
    """Input validation errors"""

    def __init__(self, field: str, message: str, value: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"Validation error for {field}: {message}", "VALIDATION_ERROR", details)
        self.field = field
        self.value = value


class ConfigurationError(CM04ScannerError):
    """Configuration related errors"""

    def __init__(self, config_key: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"Configuration error for {config_key}: {message}", "CONFIGURATION_ERROR", details)
        self.config_key = config_key


class ReportGenerationError(CM04ScannerError):
    """Report generation errors"""

    def __init__(self, job_id: str, report_type: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"Failed to generate {report_type} report for job {job_id}: {message}", "REPORT_GENERATION_ERROR", details)
        self.job_id = job_id
        self.report_type = report_type


class FileUploadError(CM04ScannerError):
    """File upload related errors"""

    def __init__(self, filename: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"File upload error for {filename}: {message}", "FILE_UPLOAD_ERROR", details)
        self.filename = filename


class FileFormatError(FileUploadError):
    """File format validation errors"""

    def __init__(self, filename: str, expected_format: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(filename, f"Invalid file format, expected {expected_format}", details)
        self.expected_format = expected_format


class RateLimitError(CM04ScannerError):
    """Rate limiting errors"""

    def __init__(self, limit: int, window: int, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"Rate limit exceeded: {limit} requests per {window} seconds", "RATE_LIMIT_ERROR", details)
        self.limit = limit
        self.window = window


class DatabaseError(CM04ScannerError):
    """Database related errors"""

    def __init__(self, operation: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"Database error during {operation}: {message}", "DATABASE_ERROR", details)
        self.operation = operation


class CacheError(CM04ScannerError):
    """Cache related errors"""

    def __init__(self, cache_key: str, operation: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"Cache {operation} error for key {cache_key}: {message}", "CACHE_ERROR", details)
        self.cache_key = cache_key
        self.operation = operation


class WebSocketError(CM04ScannerError):
    """WebSocket related errors"""

    def __init__(self, connection_id: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"WebSocket error for connection {connection_id}: {message}", "WEBSOCKET_ERROR", details)
        self.connection_id = connection_id


class AuthenticationError(CM04ScannerError):
    """Authentication related errors"""

    def __init__(self, method: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"Authentication error ({method}): {message}", "AUTHENTICATION_ERROR", details)
        self.method = method


class AuthorizationError(CM04ScannerError):
    """Authorization related errors"""

    def __init__(self, user_id: str, resource: str, action: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"User {user_id} not authorized to {action} on {resource}", "AUTHORIZATION_ERROR", details)
        self.user_id = user_id
        self.resource = resource
        self.action = action


def handle_exception(exc: Exception, context: Optional[Dict[str, Any]] = None) -> CM04ScannerError:
    """Convert any exception to a CM04ScannerError with context"""
    if isinstance(exc, CM04ScannerError):
        if context:
            exc.details.update(context)
        return exc

    # Handle common Python exceptions
    if isinstance(exc, ConnectionError):
        return CM04ScannerError(f"Connection error: {str(exc)}", "CONNECTION_ERROR", context)
    elif isinstance(exc, TimeoutError):
        return CM04ScannerError(f"Timeout error: {str(exc)}", "TIMEOUT_ERROR", context)
    elif isinstance(exc, PermissionError):
        return CM04ScannerError(f"Permission denied: {str(exc)}", "PERMISSION_ERROR", context)
    elif isinstance(exc, FileNotFoundError):
        return CM04ScannerError(f"File not found: {str(exc)}", "FILE_NOT_FOUND", context)
    elif isinstance(exc, ValueError):
        return CM04ScannerError(f"Invalid value: {str(exc)}", "INVALID_VALUE", context)
    elif isinstance(exc, KeyError):
        return CM04ScannerError(f"Missing required key: {str(exc)}", "MISSING_KEY", context)
    else:
        return CM04ScannerError(f"Unexpected error: {str(exc)}", "UNEXPECTED_ERROR", context)