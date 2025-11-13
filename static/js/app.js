// CM-04 Scanner Frontend JavaScript

class CM04Scanner {
    constructor() {
        this.currentJobId = null;
        this.websocket = null;
        this.selectedFiles = [];
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadExistingJobs();
    }

    setupEventListeners() {
        // Tab switching
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
        });

        // File upload
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');

        uploadArea.addEventListener('click', () => fileInput.click());
        uploadArea.addEventListener('dragover', (e) => this.handleDragOver(e));
        uploadArea.addEventListener('dragleave', (e) => this.handleDragLeave(e));
        uploadArea.addEventListener('drop', (e) => this.handleFileDrop(e));

        fileInput.addEventListener('change', (e) => this.handleFileSelect(e.target.files));

        // Scan buttons
        document.getElementById('scanFromFileButton').addEventListener('click', () => this.scanFromFile());
        document.getElementById('scanManualButton').addEventListener('click', () => this.scanFromManual());

        // Add first host entry for manual mode
        this.addHostEntry();
    }

    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${tabName}Tab`).classList.add('active');
    }

    handleDragOver(e) {
        e.preventDefault();
        e.stopPropagation();
        document.getElementById('uploadArea').classList.add('drag-over');
    }

    handleDragLeave(e) {
        e.preventDefault();
        e.stopPropagation();
        document.getElementById('uploadArea').classList.remove('drag-over');
    }

    handleFileDrop(e) {
        e.preventDefault();
        e.stopPropagation();
        document.getElementById('uploadArea').classList.remove('drag-over');

        const files = Array.from(e.dataTransfer.files);
        this.handleFileSelect(files);
    }

    handleFileSelect(files) {
        const validFiles = Array.from(files).filter(file =>
            file.name.endsWith('.csv') ||
            file.name.endsWith('.txt') ||
            file.name.endsWith('.json')
        );

        if (validFiles.length === 0) {
            this.showError('Please select valid files (.csv, .txt, .json)');
            return;
        }

        this.selectedFiles = validFiles;
        this.displayFilePreview();
    }

    displayFilePreview() {
        const filePreview = document.getElementById('filePreview');
        const fileList = document.getElementById('fileList');
        const uploadArea = document.getElementById('uploadArea');

        // Clear previous list
        fileList.innerHTML = '';

        // Display selected files
        this.selectedFiles.forEach(file => {
            const li = document.createElement('li');
            li.textContent = `${file.name} (${this.formatFileSize(file.size)})`;
            fileList.appendChild(li);
        });

        // Show preview, hide upload area
        filePreview.style.display = 'block';
        uploadArea.style.display = 'none';
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async scanFromFile() {
        if (this.selectedFiles.length === 0) {
            this.showError('Please select files first');
            return;
        }

        const jobName = document.getElementById('jobName').value;

        try {
            this.showLoading('Uploading files and starting scan...');

            const formData = new FormData();
            formData.append('file', this.selectedFiles[0]);
            if (jobName) {
                formData.append('job_name', jobName);
            }

            const response = await fetch('/api/v1/scan/upload', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.detail || 'Scan submission failed');
            }

            this.hideLoading();
            this.startJobMonitoring(result.job_id);

            this.addDebugLog('info', `Scan job submitted: ${result.job_id}`);

        } catch (error) {
            this.hideLoading();
            this.showError(`Failed to start scan: ${error.message}`);
            this.addDebugLog('error', `Scan submission failed: ${error.message}`);
        }
    }

    async scanFromManual() {
        const jobName = document.getElementById('jobNameManual').value;
        const hostEntries = document.querySelectorAll('.host-entry');

        const hosts = [];
        let hasError = false;

        hostEntries.forEach(entry => {
            const hostname = entry.querySelector('.hostname-input').value.trim();
            const paths = entry.querySelector('.paths-input').value.trim();

            if (hostname && paths) {
                const codePaths = paths.split(',').map(p => p.trim()).filter(p => p);
                if (codePaths.length > 0) {
                    hosts.push({ hostname, code_paths: codePaths });
                } else {
                    hasError = true;
                }
            }
        });

        if (hosts.length === 0) {
            this.showError('Please add at least one host with code paths');
            return;
        }

        if (hasError) {
            this.showError('Please provide valid code paths for all hosts');
            return;
        }

        try {
            this.showLoading('Submitting scan request...');

            const response = await fetch('/api/v1/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    hosts: hosts,
                    job_name: jobName
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.detail || 'Scan submission failed');
            }

            this.hideLoading();
            this.startJobMonitoring(result.job_id);

            this.addDebugLog('info', `Manual scan job submitted: ${result.job_id}`);

        } catch (error) {
            this.hideLoading();
            this.showError(`Failed to start scan: ${error.message}`);
            this.addDebugLog('error', `Manual scan submission failed: ${error.message}`);
        }
    }

    startJobMonitoring(jobId) {
        this.currentJobId = jobId;

        // Show progress section
        document.getElementById('uploadSection').style.display = 'none';
        document.getElementById('progressSection').style.display = 'block';
        document.getElementById('resultsSection').style.display = 'none';

        // Set initial job info
        document.getElementById('jobId').textContent = `Job ID: ${jobId}`;
        document.getElementById('jobStatus').textContent = 'RUNNING';
        document.getElementById('jobStatus').className = 'job-status';

        // Connect to WebSocket for real-time updates
        this.connectWebSocket(jobId);

        // Start polling for job status (fallback)
        this.startStatusPolling(jobId);
    }

    connectWebSocket(jobId) {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/jobs/${jobId}`;

        try {
            this.websocket = new WebSocket(wsUrl);

            this.websocket.onopen = () => {
                this.addDebugLog('info', `WebSocket connected for job ${jobId}`);
            };

            this.websocket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleJobUpdate(data);
                } catch (error) {
                    this.addDebugLog('error', `Failed to parse WebSocket message: ${error.message}`);
                }
            };

            this.websocket.onclose = () => {
                this.addDebugLog('info', `WebSocket disconnected for job ${jobId}`);
            };

            this.websocket.onerror = (error) => {
                this.addDebugLog('error', `WebSocket error: ${error}`);
            };

        } catch (error) {
            this.addDebugLog('error', `Failed to connect WebSocket: ${error.message}`);
        }
    }

    handleJobUpdate(data) {
        if (data.type === 'progress') {
            this.updateProgress(data);
        } else if (data.type === 'completed') {
            this.handleJobCompleted(data);
        } else if (data.type === 'error') {
            this.handleJobError(data);
        }
    }

    updateProgress(data) {
        const { completed_hosts, total_hosts, current_host } = data;

        document.getElementById('progressText').textContent = `${completed_hosts} / ${total_hosts} hosts completed`;

        const percent = total_hosts > 0 ? Math.round((completed_hosts / total_hosts) * 100) : 0;
        document.getElementById('progressPercent').textContent = `${percent}%`;
        document.getElementById('progressFill').style.width = `${percent}%`;

        if (current_host) {
            document.getElementById('currentHost').textContent = `Scanning: ${current_host}`;
        }

        // Update summary cards if results section is visible
        if (document.getElementById('resultsSection').style.display !== 'none') {
            document.getElementById('completedHosts').textContent = completed_hosts;
            document.getElementById('totalHosts').textContent = total_hosts;
        }
    }

    async handleJobCompleted(data) {
        document.getElementById('jobStatus').textContent = 'COMPLETED';
        document.getElementById('jobStatus').className = 'job-status completed';
        document.getElementById('currentHost').textContent = 'Scan completed!';

        // Close WebSocket
        if (this.websocket) {
            this.websocket.close();
        }

        // Load and display results
        await this.loadJobResults();
    }

    handleJobError(data) {
        document.getElementById('jobStatus').textContent = 'FAILED';
        document.getElementById('jobStatus').className = 'job-status failed';
        document.getElementById('currentHost').textContent = `Error: ${data.error_message || 'Unknown error'}`;

        // Close WebSocket
        if (this.websocket) {
            this.websocket.close();
        }

        this.showError(`Scan failed: ${data.error_message || 'Unknown error'}`);
    }

    startStatusPolling(jobId) {
        const pollInterval = setInterval(async () => {
            try {
                const response = await fetch(`/api/v1/jobs/${jobId}/progress`);
                if (!response.ok) {
                    clearInterval(pollInterval);
                    return;
                }

                const progress = await response.json();
                this.updateProgress(progress);

                if (progress.status === 'completed' || progress.status === 'failed') {
                    clearInterval(pollInterval);

                    if (progress.status === 'completed') {
                        await this.loadJobResults();
                    } else {
                        this.handleJobError(progress);
                    }
                }

            } catch (error) {
                this.addDebugLog('error', `Status polling failed: ${error.message}`);
            }
        }, 5000); // Poll every 5 seconds

        // Clear polling after 1 hour
        setTimeout(() => clearInterval(pollInterval), 3600000);
    }

    async loadJobResults() {
        if (!this.currentJobId) return;

        try {
            const response = await fetch(`/api/v1/jobs/${this.currentJobId}`);
            if (!response.ok) {
                throw new Error('Failed to load job results');
            }

            const jobResult = await response.json();
            this.displayResults(jobResult);

        } catch (error) {
            this.showError(`Failed to load results: ${error.message}`);
            this.addDebugLog('error', `Failed to load results: ${error.message}`);
        }
    }

    displayResults(jobResult) {
        // Show results section
        document.getElementById('progressSection').style.display = 'none';
        document.getElementById('resultsSection').style.display = 'block';

        // Update summary cards
        document.getElementById('totalHosts').textContent = jobResult.total_hosts;
        document.getElementById('completedHosts').textContent = jobResult.completed_hosts;
        document.getElementById('failedHosts').textContent = jobResult.failed_hosts;

        // Calculate total users with access
        const totalUsers = jobResult.results.reduce((sum, host) =>
            sum + host.users_with_access.length, 0);
        document.getElementById('totalUsers').textContent = totalUsers;

        // Populate results table
        const tableBody = document.getElementById('resultsTableBody');
        tableBody.innerHTML = '';

        jobResult.results.forEach(hostResult => {
            if (hostResult.users_with_access.length === 0) {
                // Add row for host with no access
                const row = tableBody.insertRow();
                row.innerHTML = `
                    <td>${hostResult.hostname}</td>
                    <td>${hostResult.code_path}</td>
                    <td colspan="4" style="text-align: center; color: #6c757d;">
                        ${hostResult.error_message || 'No users with write access'}
                    </td>
                `;
            } else {
                hostResult.users_with_access.forEach(access => {
                    const row = tableBody.insertRow();
                    row.innerHTML = `
                        <td>${hostResult.hostname}</td>
                        <td>${hostResult.code_path}</td>
                        <td>${access.user_id}</td>
                        <td>${access.login_method}</td>
                        <td>${access.privilege_type}</td>
                        <td>${access.privilege_source}</td>
                    `;
                });
            }
        });

        this.addDebugLog('info', `Results displayed for ${jobResult.total_hosts} hosts`);
    }

    async downloadReport(format) {
        if (!this.currentJobId) {
            this.showError('No job selected for report generation');
            return;
        }

        try {
            this.showLoading(`Generating ${format.toUpperCase()} report...`);

            // Generate reports first
            const generateResponse = await fetch(`/api/v1/jobs/${this.currentJobId}/reports/generate`, {
                method: 'POST'
            });

            if (!generateResponse.ok) {
                throw new Error('Failed to generate reports');
            }

            // Wait a moment for report generation
            await new Promise(resolve => setTimeout(resolve, 2000));

            // Get available reports
            const reportsResponse = await fetch(`/api/v1/jobs/${this.currentJobId}/reports`);
            const reportsData = await reportsResponse.json();

            const report = reportsData.reports.find(r => r.type === format);
            if (!report) {
                throw new Error(`${format.toUpperCase()} report not found`);
            }

            if (format === 'html') {
                // Open HTML report in new tab
                window.open(report.url, '_blank');
            } else {
                // Download CSV/JSON
                window.open(report.url, '_blank');
            }

            this.hideLoading();
            this.addDebugLog('info', `${format.toUpperCase()} report generated successfully`);

        } catch (error) {
            this.hideLoading();
            this.showError(`Failed to generate ${format.toUpperCase()} report: ${error.message}`);
            this.addDebugLog('error', `Report generation failed: ${error.message}`);
        }
    }

    newScan() {
        // Reset form
        this.selectedFiles = [];
        this.currentJobId = null;

        if (this.websocket) {
            this.websocket.close();
        }

        // Show upload section, hide others
        document.getElementById('uploadSection').style.display = 'block';
        document.getElementById('progressSection').style.display = 'none';
        document.getElementById('resultsSection').style.display = 'none';

        // Reset file upload
        document.getElementById('filePreview').style.display = 'none';
        document.getElementById('uploadArea').style.display = 'block';
        document.getElementById('fileInput').value = '';
        document.getElementById('jobName').value = '';
        document.getElementById('jobNameManual').value = '';

        // Clear manual entries
        const hostEntries = document.getElementById('hostEntries');
        hostEntries.innerHTML = '';
        this.addHostEntry();

        this.addDebugLog('info', 'Ready for new scan');
    }

    async loadExistingJobs() {
        try {
            const response = await fetch('/api/v1/jobs?limit=10');
            if (response.ok) {
                const data = await response.json();
                this.addDebugLog('info', `Loaded ${data.jobs.length} existing jobs`);
            }
        } catch (error) {
            this.addDebugLog('error', `Failed to load existing jobs: ${error.message}`);
        }
    }

    addHostEntry() {
        const hostEntries = document.getElementById('hostEntries');
        const entry = document.createElement('div');
        entry.className = 'host-entry';
        entry.innerHTML = `
            <input type="text" placeholder="Hostname" class="hostname-input">
            <input type="text" placeholder="Code paths (comma-separated)" class="paths-input">
            <button class="remove-button" onclick="this.parentElement.remove()">×</button>
        `;
        hostEntries.appendChild(entry);
    }

    clearDebugLogs() {
        document.getElementById('debugLogs').textContent = '';
        this.addDebugLog('info', 'Debug logs cleared');
    }

    toggleDebugConsole() {
        const debugConsole = document.getElementById('debugConsole');
        debugConsole.style.display = debugConsole.style.display === 'none' ? 'block' : 'none';
    }

    addDebugLog(level, message) {
        const debugLogs = document.getElementById('debugLogs');
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = `[${timestamp}] ${level.toUpperCase()}: ${message}\n`;
        debugLogs.textContent += logEntry;
        debugLogs.scrollTop = debugLogs.scrollHeight;

        // Also log to console for development
        console.log(`[CM-04 Scanner] ${logEntry.trim()}`);
    }

    showLoading(message = 'Loading...') {
        document.getElementById('loadingMessage').textContent = message;
        document.getElementById('loadingModal').style.display = 'block';
    }

    hideLoading() {
        document.getElementById('loadingModal').style.display = 'none';
    }

    showError(message) {
        document.getElementById('errorMessage').textContent = message;
        document.getElementById('errorModal').style.display = 'block';
        this.addDebugLog('error', message);
    }

    closeErrorModal() {
        document.getElementById('errorModal').style.display = 'none';
    }
}

// Global functions for inline event handlers
function removeHostEntry(button) {
    button.parentElement.remove();
}

function addHostEntry() {
    window.cm04Scanner.addHostEntry();
}

function downloadReport(format) {
    window.cm04Scanner.downloadReport(format);
}

function newScan() {
    window.cm04Scanner.newScan();
}

function clearDebugLogs() {
    window.cm04Scanner.clearDebugLogs();
}

function toggleDebugConsole() {
    window.cm04Scanner.toggleDebugConsole();
}

function closeErrorModal() {
    window.cm04Scanner.closeErrorModal();
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    window.cm04Scanner = new CM04Scanner();
});