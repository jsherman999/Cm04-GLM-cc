# CM-04 Scanner Deployment Guide

This guide covers deployment scenarios for the CM-04 Scanner in production environments.

## System Requirements

### Minimum Requirements
- CPU: 2 cores
- Memory: 4GB RAM
- Storage: 20GB available space
- OS: Linux (Ubuntu 20.04+, RHEL 8+, CentOS 8+)
- Python: 3.8+

### Recommended Requirements
- CPU: 4+ cores
- Memory: 8GB+ RAM
- Storage: 100GB+ SSD
- Network: Gigabit connection
- OS: Linux with systemd support

### Target Host Requirements
Target hosts must have:
- SSH server running
- Passwordless SSH access configured from scanner host
- Python 3.6+ (for advanced features)
- QAS/VAS client tools (for AD integration)

## Deployment Options

### 1. Single Server Deployment

#### Installation

1. **Create dedicated user**:
   ```bash
   sudo useradd -m -s /bin/bash cm04-scanner
   sudo usermod -aG sudo cm04-scanner
   ```

2. **Install application**:
   ```bash
   sudo -u cm04-scanner bash
   cd /home/cm04-scanner
   git clone https://github.com/your-org/cm04-scanner.git
   cd cm04-scanner
   pip install -e .
   ```

3. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with appropriate settings
   ```

4. **Setup SSH keys**:
   ```bash
   ssh-keygen -t rsa -b 4096 -C "cm04-scanner@$(hostname)"
   # Add public key to target hosts
   ```

5. **Create systemd service**:
   ```ini
   # /etc/systemd/system/cm04-scanner.service
   [Unit]
   Description=CM-04 Scanner Service
   After=network.target

   [Service]
   Type=exec
   User=cm04-scanner
   Group=cm04-scanner
   WorkingDirectory=/home/cm04-scanner/cm04-scanner
   Environment=PATH=/home/cm04-scanner/cm04-scanner/venv/bin
   ExecStart=/home/cm04-scanner/cm04-scanner/venv/bin/cm04-server --host 0.0.0.0 --port 8000
   Restart=always
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
   ```

6. **Enable and start service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable cm04-scanner
   sudo systemctl start cm04-scanner
   sudo systemctl status cm04-scanner
   ```

#### Nginx Reverse Proxy

```nginx
# /etc/nginx/sites-available/cm04-scanner
server {
    listen 80;
    server_name cm04-scanner.example.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name cm04-scanner.example.com;

    ssl_certificate /path/to/ssl/cert.pem;
    ssl_certificate_key /path/to/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 2. Docker Deployment

#### Dockerfile

```dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1000 cm04-scanner

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set ownership
RUN chown -R cm04-scanner:cm04-scanner /app

# Switch to app user
USER cm04-scanner

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start application
CMD ["cm04-server", "--host", "0.0.0.0", "--port", "8000"]
```

#### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  cm04-scanner:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql+asyncpg://postgres:password@db:5432/cm04scanner
      - REDIS_URL=redis://redis:6379
      - SECRET_KEY=${SECRET_KEY}
    volumes:
      - ./uploads:/app/uploads
      - ./reports:/app/reports
      - ./logs:/app/logs
      - ~/.ssh:/home/cm04-scanner/.ssh:ro
    depends_on:
      - db
      - redis
    restart: unless-stopped

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=cm04scanner
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - cm04-scanner
    restart: unless-stopped

volumes:
  postgres_data:
```

#### Deployment Commands

```bash
# Build and start
docker-compose up -d --build

# View logs
docker-compose logs -f cm04-scanner

# Scale for high availability
docker-compose up -d --scale cm04-scanner=3
```

### 3. Kubernetes Deployment

#### Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cm04-scanner
```

#### ConfigMap

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm04-scanner-config
  namespace: cm04-scanner
data:
  DATABASE_URL: "postgresql+asyncpg://postgres:password@postgres:5432/cm04scanner"
  REDIS_URL: "redis://redis:6379"
  SSH_CONCURRENCY_LIMIT: "50"
  LOG_LEVEL: "INFO"
```

#### Secret

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: cm04-scanner-secrets
  namespace: cm04-scanner
type: Opaque
data:
  SECRET_KEY: <base64-encoded-secret>
  POSTGRES_PASSWORD: <base64-encoded-password>
```

#### Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cm04-scanner
  namespace: cm04-scanner
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cm04-scanner
  template:
    metadata:
      labels:
        app: cm04-scanner
    spec:
      containers:
      - name: cm04-scanner
        image: your-registry/cm04-scanner:latest
        ports:
        - containerPort: 8000
        envFrom:
        - configMapRef:
            name: cm04-scanner-config
        - secretRef:
            name: cm04-scanner-secrets
        volumeMounts:
        - name: ssh-keys
          mountPath: /home/cm04-scanner/.ssh
          readOnly: true
        - name: uploads
          mountPath: /app/uploads
        - name: reports
          mountPath: /app/reports
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: ssh-keys
        secret:
          secretName: cm04-scanner-ssh-keys
          defaultMode: 0600
      - name: uploads
        persistentVolumeClaim:
          claimName: cm04-scanner-uploads
      - name: reports
        persistentVolumeClaim:
          claimName: cm04-scanner-reports
```

#### Service

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: cm04-scanner-service
  namespace: cm04-scanner
spec:
  selector:
    app: cm04-scanner
  ports:
  - name: http
    port: 80
    targetPort: 8000
  type: ClusterIP
```

#### Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cm04-scanner-ingress
  namespace: cm04-scanner
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "100m"
spec:
  tls:
  - hosts:
    - cm04-scanner.example.com
    secretName: cm04-scanner-tls
  rules:
  - host: cm04-scanner.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: cm04-scanner-service
            port:
              number: 80
```

## Configuration

### Environment Variables

Key production configuration variables:

```bash
# Application
APP_NAME="CM-04 Scanner"
DEBUG=false
LOG_LEVEL=INFO

# Security
SECRET_KEY="your-secure-random-secret-key"
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database
DATABASE_URL="postgresql+asyncpg://user:pass@host:5432/dbname"

# Performance
SSH_CONCURRENCY_LIMIT=50
MAX_CONCURRENT_JOBS=5
CONNECTION_POOL_SIZE=20

# Storage
UPLOAD_DIR="/data/uploads"
REPORTS_DIR="/data/reports"
MAX_FILE_SIZE=104857600  # 100MB

# External Services
REDIS_URL="redis://redis:6379"
WEBHOOK_URL="https://your-webhook-url.com"
```

### Database Setup

#### PostgreSQL

```sql
-- Create database and user
CREATE DATABASE cm04scanner;
CREATE USER cm04scanner WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE cm04scanner TO cm04scanner;

-- Connect to cm04scanner database
\c cm04scanner

-- Grant schema permissions
GRANT ALL ON SCHEMA public TO cm04scanner;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cm04scanner;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cm04scanner;
```

#### Database Migration

```bash
# Run database migrations (if using Alembic)
alembic upgrade head

# Or let the application create tables automatically
cm04-server --init-db
```

## Security Configuration

### SSH Security

1. **Dedicated SSH Key**:
   ```bash
   ssh-keygen -t ed25519 -C "cm04-scanner@$(hostname)"
   # Use strong passphrase and secure storage
   ```

2. **Key Management**:
   ```bash
   # Set proper permissions
   chmod 600 ~/.ssh/id_ed25519
   chmod 644 ~/.ssh/id_ed25519.pub
   chmod 700 ~/.ssh
   ```

3. **Authorized Keys on Target Hosts**:
   ```bash
   # Add to target host's authorized_keys with restrictions
   command="/usr/lib/openssh/sftp-server",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAAC3Nz... cm04-scanner@jump-server
   ```

### Network Security

#### Firewall Configuration

```bash
# UFW example
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

#### SSL/TLS Configuration

```nginx
# Strong SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
```

### Access Control

```bash
# File permissions
chmod 750 /home/cm04-scanner
chmod 755 /home/cm04-scanner/cm04-scanner
chmod 600 /home/cm04-scanner/.env
chmod 755 /home/cm04-scanner/cm04-scanner/logs
chmod 755 /home/cm04-scanner/cm04-scanner/uploads
chmod 755 /home/cm04-scanner/cm04-scanner/reports
```

## Monitoring and Logging

### Application Monitoring

#### Prometheus Metrics

```python
# Add to requirements.txt
prometheus-client>=0.19.0

# Metrics configuration in settings.py
ENABLE_METRICS=true
METRICS_PORT=9090
```

#### Health Checks

```bash
# Application health endpoint
curl -f http://localhost:8000/health

# Detailed health check
curl -f http://localhost:8000/health/detailed
```

### Log Management

#### Log Rotation

```bash
# /etc/logrotate.d/cm04-scanner
/home/cm04-scanner/cm04-scanner/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su cm04-scanner cm04-scanner
}
```

#### Centralized Logging

```yaml
# Fluentd configuration for log forwarding
<source>
  @type tail
  path /home/cm04-scanner/cm04-scanner/logs/*.log
  pos_file /var/log/fluentd/cm04-scanner.log.pos
  tag cm04-scanner.*
  format json
</source>

<match cm04-scanner.**>
  @type elasticsearch
  host elasticsearch.example.com
  port 9200
  index_name cm04-scanner
</match>
```

### Performance Monitoring

#### System Metrics

```bash
# Resource usage monitoring
htop
iostat -x 1
netstat -an | grep :8000

# Application-specific monitoring
ps aux | grep cm04-scanner
ss -tuln | grep :8000
```

## Backup and Recovery

### Data Backup

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backup/cm04-scanner"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR/$DATE

# Backup application files
tar -czf $BACKUP_DIR/$DATE/application.tar.gz \
  /home/cm04-scanner/cm04-scanner

# Backup database
pg_dump cm04scanner | gzip > $BACKUP_DIR/$DATE/database.sql.gz

# Backup configuration files
cp /home/cm04-scanner/.env $BACKUP_DIR/$DATE/
cp /etc/systemd/system/cm04-scanner.service $BACKUP_DIR/$DATE/

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -type d -mtime +30 -exec rm -rf {} \;
```

### Recovery

```bash
#!/bin/bash
# restore.sh

BACKUP_DATE=$1
BACKUP_DIR="/backup/cm04-scanner/$BACKUP_DATE"

if [ -z "$BACKUP_DATE" ]; then
    echo "Usage: $0 <backup_date>"
    exit 1
fi

# Stop service
sudo systemctl stop cm04-scanner

# Restore application files
sudo -u cm04-scanner tar -xzf $BACKUP_DIR/application.tar.gz -C /home/cm04-scanner/

# Restore database
gunzip -c $BACKUP_DIR/database.sql.gz | psql cm04scanner

# Restore configuration
sudo cp $BACKUP_DIR/.env /home/cm04-scanner/
sudo cp $BACKUP_DIR/cm04-scanner.service /etc/systemd/system/

# Start service
sudo systemctl daemon-reload
sudo systemctl start cm04-scanner
```

## Troubleshooting

### Common Issues

#### SSH Connection Failures

```bash
# Test SSH connectivity
ssh -v target-host "echo 'test'"

# Check SSH key permissions
ls -la ~/.ssh/

# Verify target host access
ssh-keyscan -t rsa target-host >> ~/.ssh/known_hosts
```

#### Performance Issues

```bash
# Check system resources
free -h
df -h
top

# Check application logs
tail -f /home/cm04-scanner/cm04-scanner/logs/cm04_scanner.log

# Check network connections
netstat -an | grep :8000
ss -tuln | grep :8000
```

#### Database Issues

```bash
# Check database connection
psql -h localhost -U cm04scanner -d cm04scanner

# Check database size
SELECT pg_size_pretty(pg_database_size('cm04scanner'));

# Check active connections
SELECT count(*) FROM pg_stat_activity WHERE datname = 'cm04scanner';
```

### Debug Mode

```bash
# Enable debug logging
export DEBUG=true
export LOG_LEVEL=DEBUG

# Run with verbose output
cm04-server --debug --log-level DEBUG
```

---

For additional support, see the [main documentation](../README.md) or create an issue in the project repository.