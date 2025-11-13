# CM-04 Scanner

A comprehensive Linux host access control analysis tool for CM-04 compliance monitoring. This application scans multiple Linux hosts to determine which users have write access to specified code paths through filesystem permissions, group memberships, or sudo capabilities.

## Features

- **Multi-Host Scanning**: Concurrently scan multiple Linux hosts with configurable connection limits
- **SSH Multiplexing**: Efficient SSH connection pooling with up to 100 concurrent sessions
- **AD Integration**: QAS/VAS support for domain-joined hosts via `vastool` commands
- **Real-time Progress**: WebSocket-based progress tracking with live updates
- **Modern Web Interface**: Drag-and-drop file upload with responsive design
- **Comprehensive Reporting**: CSV, JSON, HTML, and compliance matrix reports
- **CLI Tools**: Full command-line interface for automation and scripting
- **Audit Logging**: Complete audit trail of all scan operations
- **API-First Design**: RESTful API with OpenAPI documentation

## Quick Start

### Prerequisites

- Python 3.8+
- SSH access to target hosts with passwordless authentication configured
- QAS/VAS integration (optional, for AD domain joined hosts)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-org/cm04-scanner.git
   cd cm04-scanner
   ```

2. **Install dependencies**:
   ```bash
   pip install -e .
   ```

3. **Configure the application**:
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

4. **Start the server**:
   ```bash
   cm04-server --host 0.0.0.0 --port 8000
   ```

5. **Access the web interface**:
   Open http://localhost:8000 in your browser

### Basic Usage

#### Web Interface

1. Navigate to http://localhost:8000
2. Either upload a file with host and path information or enter manually
3. Click "Start Scan" to begin
4. Monitor progress in real-time
5. Download reports when complete

#### Command Line Interface

```bash
# Scan a single host
cm04-scan scan -h server.example.com -p "/home,/var/log"

# Scan from file
cm04-scan scan-file hosts.txt --job-name "Weekly Compliance Scan"

# Monitor job progress
cm04-scan status abc123-job-id --watch

# Download reports
cm04-scan report abc123-job-id --format csv
cm04-scan report abc123-job-id --format html --open

# Monitor multiple jobs
cm04-monitor jobs abc123 def456 ghi789
```

## Configuration

### Environment Variables

Key configuration options in `.env`:

```env
# SSH Settings
SSH_TIMEOUT=30
SSH_CONCURRENCY_LIMIT=100
SSH_USER=scanner
SSH_KEY_FILE=~/.ssh/id_rsa

# Database
DATABASE_URL=sqlite+aiosqlite:///./cm04_scanner.db

# QAS/VAS Integration
VASTOOL_PATH=/opt/quest/bin/vastool

# Security
SECRET_KEY=your-random-secret-key
```

### Host File Formats

**Important:** Each host entry should specify ONE code path. To scan multiple paths on the same host, create separate entries.

#### CSV Format
```csv
server1.example.com,/home
server1.example.com,/var/log
server2.example.com,/data
server3.example.com,/usr/local/bin
```

#### JSON Format
```json
[
  {
    "hostname": "server1.example.com",
    "code_paths": ["/home"]
  },
  {
    "hostname": "server1.example.com",
    "code_paths": ["/var/log"]
  },
  {
    "hostname": "server2.example.com",
    "code_paths": ["/data"]
  }
]
```

#### Plain Text Format
```
server1.example.com /home
server1.example.com /var/log
server2.example.com /data
server3.example.com /usr/local/bin
```

## API Documentation

### Submit Scan Job

```bash
curl -X POST "http://localhost:8000/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "hosts": [
      {
        "hostname": "server1.example.com",
        "code_paths": ["/home", "/var/log"]
      }
    ],
    "job_name": "Test Scan"
  }'
```

### Upload File

```bash
curl -X POST "http://localhost:8000/api/v1/scan/upload" \
  -F "file=@hosts.txt" \
  -F "job_name=File Upload Scan"
```

### Get Job Status

```bash
curl "http://localhost:8000/api/v1/jobs/{job_id}"
```

### Download Reports

```bash
curl "http://localhost:8000/reports/cm04_report_{job_id}.csv"
```

## Architecture

### Core Components

- **SSH Engine**: AsyncSSH-based connection pooling and command execution
- **Access Analyzer**: Filesystem permission analysis with QAS/VAS integration
- **Report Generator**: Multi-format report generation (CSV, JSON, HTML)
- **FastAPI Backend**: RESTful API with WebSocket support
- **Web Interface**: Modern React-based frontend
- **CLI Tools**: Command-line utilities for automation

### Data Flow

1. **Job Submission**: User submits scan request via web UI or CLI
2. **Host Processing**: SSH engine connects to hosts in batches (10 concurrent)
3. **Permission Analysis**: Filesystem and AD group permissions analyzed
4. **Real-time Updates**: WebSocket streams progress to clients
5. **Report Generation**: Multiple format reports created on completion
6. **Audit Logging**: All operations logged for compliance

### Security Features

- SSH key-based authentication only
- Input validation and sanitization
- Rate limiting and connection throttling
- Comprehensive audit logging
- Secure credential management
- CORS protection for API

## Access Detection Methods

The scanner detects write access through three methods:

1. **Filesystem Permissions**: Direct write permissions on files/directories
2. **Group Memberships**: Write access through group permissions
3. **Sudo Capabilities**: Users who can escalate privileges to write

### QAS/VAS Integration

For AD domain-joined hosts, the scanner:
- Uses `vastool info acl` to get ACL permissions
- Queries AD group memberships via `vastool group list`
- Resolves nested group memberships
- Tracks domain vs local login methods

## Report Formats

### CSV Report
```csv
hostname,code_path,user_id,login_method,privilege_type,priv_granting_access,scan_timestamp
server1,/home,john.doe,local,owner,owner,2024-01-15T10:30:00Z
server1,/home,domain_users,domain,group,DOMAIN\Developers,2024-01-15T10:30:00Z
server1,/var/log,admin,local,sudo,sudo,2024-01-15T10:30:00Z
```

### JSON Report
Detailed JSON format with metadata, summaries, and full result data.

### HTML Report
Interactive HTML report with charts, filtering, and export options.

### Compliance Matrix
Host-by-host compliance matrix with risk assessment.

## Monitoring and Troubleshooting

### Debug Console

The web interface includes a debug console that shows:
- Real-time SSH connection logs
- Command execution details
- Error messages and stack traces
- Performance metrics

### Log Files

Log files are automatically created in the `./logs` directory when the server starts:

- `logs/cm04_scanner.log` - General application logs
- `logs/cm04_scanner_errors.log` - Error-level logs only
- `logs/ssh_operations.log` - SSH connection and command logs
- `logs/access_analysis.log` - Permission analysis details
- `logs/api_requests.log` - API request/response logs
- `logs/audit.log` - Security audit events

**Note:** The `logs/` directory is created automatically on first run. Log files use rotation (max 10-100MB per file) to prevent disk space issues.

### Health Check

```bash
curl "http://localhost:8000/health"
```

### Performance Monitoring

Monitor resource usage with built-in metrics:
- Connection pool utilization
- Job queue length
- Memory and CPU usage
- Response time statistics

## Security Considerations

### SSH Key Management
- Use dedicated scanner service account
- Rotate SSH keys regularly
- Limit key permissions to read-only
- Use SSH key passphrase protection

### Network Security
- Deploy in trusted network zone
- Use firewall rules to restrict access
- Enable TLS for API connections in production
- Regular security updates and patches

### Data Protection
- Encrypt sensitive configuration data
- Implement secure audit log storage
- Regular backup of scan results
- Data retention policy compliance

## Development

### Running in Development Mode

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run with auto-reload
cm04-server --reload --debug

# Run tests
pytest

# Code formatting
black src/
isort src/

# Type checking
mypy src/
```

### Project Structure

```
cm04-scanner/
├── src/
│   ├── api/              # FastAPI application
│   ├── cli/              # Command-line tools
│   ├── core/             # Core scanning logic
│   ├── models/           # Pydantic schemas
│   ├── utils/            # Utilities and helpers
│   └── config/           # Configuration management
├── static/               # Web UI assets
├── tests/                # Test suite
├── docs/                 # Documentation
├── config/               # Configuration files
└── requirements.txt      # Python dependencies
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: https://cm04-scanner.readthedocs.io/
- **Issues**: https://github.com/your-org/cm04-scanner/issues
- **Discussions**: https://github.com/your-org/cm04-scanner/discussions

## Changelog

### v1.0.0 (2024-01-15)

- Initial release
- Multi-host SSH scanning with AsyncSSH
- QAS/VAS AD integration
- Web interface with drag-drop upload
- CLI tools for automation
- Comprehensive reporting
- Real-time progress tracking
- Audit logging
- RESTful API with WebSocket support

---

**CM-04 Scanner** - Your comprehensive Linux access control compliance tool.