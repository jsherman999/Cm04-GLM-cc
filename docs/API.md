# CM-04 Scanner API Documentation

The CM-04 Scanner provides a comprehensive RESTful API for submitting scan jobs, monitoring progress, and retrieving results. The API follows OpenAPI 3.0 specification and includes WebSocket support for real-time updates.

## Base URL

```
http://localhost:8000/api/v1
```

## Authentication

Currently, the API does not require authentication. This will be enhanced in future versions to support:

- JWT token authentication
- API key authentication
- OAuth 2.0 integration

## Response Format

All API responses follow a consistent format:

### Success Responses
```json
{
  "data": { ... },
  "message": "Operation completed successfully"
}
```

### Error Responses
```json
{
  "error": "Error message",
  "error_code": "ERROR_CODE",
  "details": { ... },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## HTTP Status Codes

- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Access denied
- `404 Not Found` - Resource not found
- `422 Unprocessable Entity` - Validation error
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

## Endpoints

### Scan Operations

#### Submit Scan Job

Submit a new CM-04 scan job with host and path information.

**Endpoint**: `POST /scan`

**Request Body**:
```json
{
  "hosts": [
    {
      "hostname": "server1.example.com",
      "code_paths": ["/home", "/var/log", "/opt/app"]
    },
    {
      "hostname": "server2.example.com",
      "code_paths": ["/data", "/etc"]
    }
  ],
  "job_name": "Weekly Compliance Scan",
  "tags": ["production", "weekly"]
}
```

**Response**:
```json
{
  "job_id": "abc123-def456-ghi789",
  "message": "Scan job submitted successfully",
  "status_url": "/api/v1/jobs/abc123-def456-ghi789"
}
```

#### Submit Scan from File

Submit a scan job by uploading a file containing host and path information.

**Endpoint**: `POST /scan/upload`

**Request**: `multipart/form-data`
- `file`: File to upload (CSV, TXT, or JSON format)
- `job_name`: Optional job name

**Response**:
```json
{
  "job_id": "abc123-def456-ghi789",
  "message": "Scan job submitted successfully from hosts.txt",
  "hosts_count": 25,
  "status_url": "/api/v1/jobs/abc123-def456-ghi789"
}
```

### Job Management

#### Get Job Status

Retrieve the complete status and results for a specific job.

**Endpoint**: `GET /jobs/{job_id}`

**Response**:
```json
{
  "job_id": "abc123-def456-ghi789",
  "job_name": "Weekly Compliance Scan",
  "status": "completed",
  "created_at": "2024-01-15T10:30:00Z",
  "started_at": "2024-01-15T10:30:05Z",
  "completed_at": "2024-01-15T10:35:12Z",
  "total_hosts": 25,
  "completed_hosts": 24,
  "failed_hosts": 1,
  "results": [
    {
      "hostname": "server1.example.com",
      "code_path": "/home,/var/log,/opt/app",
      "users_with_access": [
        {
          "user_id": "john.doe",
          "login_method": "local",
          "privilege_type": "owner",
          "privilege_source": "owner"
        },
        {
          "user_id": "jane.smith",
          "login_method": "domain",
          "privilege_type": "group",
          "privilege_source": "DOMAIN\\Developers"
        }
      ],
      "scan_timestamp": "2024-01-15T10:32:45Z"
    }
  ],
  "error_message": null
}
```

#### Get Job Progress

Get lightweight progress information for a job.

**Endpoint**: `GET /jobs/{job_id}/progress`

**Response**:
```json
{
  "job_id": "abc123-def456-ghi789",
  "status": "running",
  "completed_hosts": 15,
  "total_hosts": 25,
  "current_host": "server20.example.com",
  "error_message": null
}
```

#### List Jobs

Retrieve a list of jobs with optional filtering.

**Endpoint**: `GET /jobs`

**Query Parameters**:
- `status`: Filter by job status (`pending`, `running`, `completed`, `failed`, `cancelled`)
- `limit`: Maximum number of jobs to return (default: 50)
- `offset`: Number of jobs to skip (default: 0)

**Response**:
```json
{
  "jobs": [
    {
      "job_id": "abc123-def456-ghi789",
      "job_name": "Weekly Compliance Scan",
      "status": "completed",
      "created_at": "2024-01-15T10:30:00Z",
      "total_hosts": 25,
      "completed_hosts": 24,
      "failed_hosts": 1
    }
  ],
  "total": 1
}
```

#### Cancel Job

Cancel a running or pending job.

**Endpoint**: `DELETE /jobs/{job_id}`

**Response**:
```json
{
  "message": "Job cancelled successfully"
}
```

### Reports

#### Get Job Reports

Get available reports for a specific job.

**Endpoint**: `GET /jobs/{job_id}/reports`

**Response**:
```json
{
  "reports": [
    {
      "type": "csv",
      "filename": "cm04_report_abc123_20240115_103012.csv",
      "url": "/reports/cm04_report_abc123_20240115_103012.csv"
    },
    {
      "type": "html",
      "filename": "cm04_report_abc123_20240115_103012.html",
      "url": "/reports/cm04_report_abc123_20240115_103012.html"
    }
  ]
}
```

#### Generate Job Reports

Trigger report generation for a completed job.

**Endpoint**: `POST /jobs/{job_id}/reports/generate`

**Response**:
```json
{
  "message": "Report generation started"
}
```

#### List All Reports

Get a list of all available reports across all jobs.

**Endpoint**: `GET /reports`

**Response**:
```json
{
  "reports": [
    {
      "filename": "cm04_report_abc123_20240115_103012.csv",
      "type": "csv",
      "size": 15420,
      "created_at": "2024-01-15T10:35:15Z",
      "download_url": "/reports/cm04_report_abc123_20240115_103012.csv"
    }
  ]
}
```

### Utilities

#### Health Check

Check the health and status of the CM-04 Scanner service.

**Endpoint**: `GET /health`

**Response**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z",
  "ssh_connections_available": 100,
  "database_connected": true
}
```

#### Test SSH Connection

Test SSH connectivity to a specific host.

**Endpoint**: `POST /test/ssh`

**Request Body**:
```json
{
  "hostname": "server1.example.com",
  "port": 22,
  "username": "scanner",
  "key_file": "/path/to/ssh/key"
}
```

**Response**:
```json
{
  "hostname": "server1.example.com",
  "connection_successful": true,
  "message": "Connection successful"
}
```

#### Debug Logs

Retrieve debug logs for troubleshooting.

**Endpoint**: `GET /debug/logs`

**Query Parameters**:
- `hostname`: Filter logs by hostname (optional)
- `limit`: Maximum number of log entries (default: 1000)

**Response**:
```json
{
  "logs": [
    {
      "timestamp": "2024-01-15T10:32:45Z",
      "level": "DEBUG",
      "hostname": "server1.example.com",
      "message": "Executing command: stat -c '%U %G %a %F' /home",
      "details": {
        "command": "stat -c '%U %G %a %F' /home",
        "exit_status": 0,
        "execution_time": 0.15
      }
    }
  ]
}
```

#### Clear Debug Logs

Clear all debug logs from memory.

**Endpoint**: `DELETE /debug/logs`

**Response**:
```json
{
  "message": "Debug logs cleared"
}
```

## WebSocket API

Real-time job progress updates are available via WebSocket connections.

### Job Progress WebSocket

Connect to receive real-time updates for a specific job.

**Endpoint**: `WS /ws/jobs/{job_id}`

**Message Format**:
```json
{
  "type": "progress|completed|error",
  "job_id": "abc123-def456-ghi789",
  "status": "running",
  "completed_hosts": 15,
  "total_hosts": 25,
  "current_host": "server20.example.com",
  "error_message": null
}
```

#### Message Types

- **progress**: Job progress update
- **completed**: Job completed successfully
- **error**: Job failed with error

### Connection Example (JavaScript)

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/jobs/abc123-def456-ghi789');

ws.onmessage = function(event) {
  const data = JSON.parse(event.data);

  switch(data.type) {
    case 'progress':
      updateProgressBar(data.completed_hosts, data.total_hosts);
      updateCurrentHost(data.current_host);
      break;

    case 'completed':
      showCompletionMessage();
      loadResults();
      break;

    case 'error':
      showErrorMessage(data.error_message);
      break;
  }
};

ws.onerror = function(error) {
  console.error('WebSocket error:', error);
};

ws.onclose = function() {
  console.log('WebSocket connection closed');
};
```

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **General API**: 100 requests per minute
- **File Upload**: 10 uploads per minute
- **SSH Connections**: 100 concurrent connections per client

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642248000
```

## Error Codes

| Error Code | Description |
|------------|-------------|
| `VALIDATION_ERROR` | Input validation failed |
| `SSH_CONNECTION_ERROR` | SSH connection failed |
| `FILESYSTEM_ERROR` | Filesystem operation failed |
| `ACCESS_ANALYSIS_ERROR` | Access analysis failed |
| `VASTOOL_ERROR` | QAS/VAS command failed |
| `JOB_ERROR` | Job operation failed |
| `JOB_NOT_FOUND` | Job not found |
| `REPORT_GENERATION_ERROR` | Report generation failed |
| `FILE_UPLOAD_ERROR` | File upload failed |
| `RATE_LIMIT_ERROR` | Rate limit exceeded |
| `CONFIGURATION_ERROR` | Configuration error |

## SDK and Client Libraries

### Python Client Example

```python
import httpx
from pathlib import Path

class CM04Client:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.client = httpx.Client()

    def submit_scan(self, hosts, job_name=None):
        response = self.client.post(
            f"{self.base_url}/api/v1/scan",
            json={"hosts": hosts, "job_name": job_name}
        )
        response.raise_for_status()
        return response.json()

    def get_job_status(self, job_id):
        response = self.client.get(f"{self.base_url}/api/v1/jobs/{job_id}")
        response.raise_for_status()
        return response.json()

# Usage
client = CM04Client()
result = client.submit_scan([
    {
        "hostname": "server1.example.com",
        "code_paths": ["/home", "/var/log"]
    }
], job_name="Test Scan")

print(f"Job ID: {result['job_id']}")
```

### Shell Script Example

```bash
#!/bin/bash

API_BASE="http://localhost:8000/api/v1"

# Submit scan job
JOB_RESPONSE=$(curl -s -X POST "$API_BASE/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "hosts": [
      {
        "hostname": "server1.example.com",
        "code_paths": ["/home", "/var/log"]
      }
    ]
  }')

JOB_ID=$(echo $JOB_RESPONSE | jq -r '.job_id')
echo "Submitted job: $JOB_ID"

# Monitor progress
while true; do
  STATUS=$(curl -s "$API_BASE/jobs/$JOB_ID/progress")
  JOB_STATUS=$(echo $STATUS | jq -r '.status')
  COMPLETED=$(echo $STATUS | jq -r '.completed_hosts')
  TOTAL=$(echo $STATUS | jq -r '.total_hosts')

  echo "Progress: $COMPLETED/$TOTAL ($JOB_STATUS)"

  if [[ "$JOB_STATUS" == "completed" || "$JOB_STATUS" == "failed" ]]; then
    break
  fi

  sleep 5
done

# Download CSV report
curl -o "report_$JOB_ID.csv" "$API_BASE/reports/cm04_report_$JOB_ID.csv"
echo "Report downloaded: report_$JOB_ID.csv"
```

## OpenAPI Specification

The complete OpenAPI 3.0 specification is available at:
```
http://localhost:8000/docs
```

This includes:
- Interactive API documentation
- Request/response examples
- Schema definitions
- Try-it-out functionality

---

For more information and examples, see the [main documentation](../README.md).