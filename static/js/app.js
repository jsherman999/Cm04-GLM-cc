// CM-04 Scanner Frontend JavaScript

class CM04Scanner {
    constructor() {
        this.currentJobId = null;
        this.parentJobId = null;
        this.websocket = null;
        this.selectedFiles = [];
        this.currentComparison = null;
        this.verboseMode = false;
        this.debugLogBuffer = [];
        this.maxDebugLines = 500; // Keep last 500 lines in buffer
        this.lastProcessedHost = null; // Track last host to avoid duplicate logging
        this.debugConsoleVisible = true;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadAuditHistory();
        // Refresh audit history every 30 seconds
        setInterval(() => this.loadAuditHistory(), 30000);
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
        document.getElementById('pathCheckButton').addEventListener('click', () => this.runPathCheck());

        // SSH Concurrency slider
        const sshConcurrencySlider = document.getElementById('sshConcurrency');
        const sshConcurrencyValue = document.getElementById('sshConcurrencyValue');
        sshConcurrencySlider.addEventListener('input', (e) => {
            sshConcurrencyValue.textContent = e.target.value;
        });

        // Path check export button
        document.getElementById('exportPathCheckButton').addEventListener('click', () => this.exportPathCheckResults());

        // Debug console toggle
        const debugToggleButton = document.getElementById('debugToggleButton');
        if (debugToggleButton) {
            debugToggleButton.addEventListener('click', () => this.toggleDebugConsole());
        }

        // Ensure debug console state matches button label
        this.setDebugConsoleVisibility(true);

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
        const sshConcurrency = parseInt(document.getElementById('sshConcurrency').value);

        try {
            this.showLoading('Uploading files and starting scan...');

            const formData = new FormData();
            formData.append('file', this.selectedFiles[0]);
            if (jobName) {
                formData.append('job_name', jobName);
            }
            formData.append('ssh_concurrency', sshConcurrency);

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
            const path = entry.querySelector('.paths-input').value.trim();

            if (hostname && path) {
                // Only one path per host - no comma splitting
                hosts.push({ hostname, code_paths: [path] });
            } else if (hostname || path) {
                // If one is filled but not the other, that's an error
                hasError = true;
            }
        });

        if (hosts.length === 0) {
            this.showError('Please add at least one host with a code path');
            return;
        }

        if (hasError) {
            this.showError('Please provide both hostname and path for all entries');
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
                    job_name: jobName,
                    ssh_concurrency: parseInt(document.getElementById('sshConcurrency').value)
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

    async runPathCheck() {
        const hostEntries = document.querySelectorAll('.host-entry');
        const hosts = [];

        hostEntries.forEach(entry => {
            const hostname = entry.querySelector('.hostname-input').value.trim();
            const path = entry.querySelector('.paths-input').value.trim();

            if (hostname && path) {
                hosts.push({ hostname, code_paths: [path] });
            }
        });

        if (hosts.length === 0) {
            this.showError('Please add at least one host with a code path');
            return;
        }

        try {
            this.showLoading('Running path check...');
            
            const response = await fetch('/api/v1/path-check', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ hosts })
            });

            const results = await response.json();

            if (!response.ok) {
                throw new Error(results.detail || 'Path check failed');
            }

            this.hideLoading();
            this.displayPathCheckResults(results);
            this.addDebugLog('info', `Path check completed: ${results.length} results`);

        } catch (error) {
            this.hideLoading();
            this.showError(`Path check failed: ${error.message}`);
            this.addDebugLog('error', `Path check failed: ${error.message}`);
        }
    }

    displayPathCheckResults(results) {
        // Filter to show only failures
        const failures = results.filter(r => r.result !== 'ok');

        // Show path check section
        document.getElementById('pathCheckSection').style.display = 'block';
        
        // Scroll to results
        document.getElementById('pathCheckSection').scrollIntoView({ behavior: 'smooth' });

        // Update status
        const statusText = failures.length === 0 
            ? 'All paths are reachable and valid!'
            : `Found ${failures.length} issue(s)`;
        document.getElementById('pathCheckStatus').textContent = statusText;

        // Populate table
        const tbody = document.getElementById('pathCheckTableBody');
        tbody.innerHTML = '';

        if (failures.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:#28a745; padding:2rem;">✓ All hosts reachable and paths valid</td></tr>';
            return;
        }

        failures.forEach(failure => {
            const row = document.createElement('tr');
            
            // Determine row class based on result
            if (failure.result === 'unreachable') {
                row.className = 'path-check-row-unreachable';
            } else if (failure.result === 'path_does_not_exist') {
                row.className = 'path-check-row-path-not-found';
            } else if (failure.result === 'path_world_writable') {
                row.className = 'path-check-row-world-writable';
            }

            row.innerHTML = `
                <td class="hostname-cell">${this.escapeHtml(failure.hostname)}</td>
                <td class="path-cell">${this.escapeHtml(failure.path)}</td>
                <td class="result-cell result-${failure.result.replace(/_/g, '-')}">${this.formatResult(failure.result)}</td>
            `;
            
            tbody.appendChild(row);
        });

        // Store results for export
        this.pathCheckResults = failures;
    }

    formatResult(result) {
        const resultMap = {
            'unreachable': 'Host Unreachable',
            'path_does_not_exist': 'Path Does Not Exist',
            'path_world_writable': 'Path World-Writable'
        };
        return resultMap[result] || result;
    }

    exportPathCheckResults() {
        if (!this.pathCheckResults || this.pathCheckResults.length === 0) {
            this.showError('No path check results to export');
            return;
        }

        // Create CSV content
        const headers = ['Hostname', 'Path', 'Result'];
        const rows = this.pathCheckResults.map(r => [
            r.hostname,
            r.path,
            this.formatResult(r.result)
        ]);

        let csvContent = headers.join(',') + '\n';
        rows.forEach(row => {
            csvContent += row.map(cell => `"${cell}"`).join(',') + '\n';
        });

        // Create download link
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        
        link.setAttribute('href', url);
        link.setAttribute('download', `path_check_failures_${new Date().toISOString().split('T')[0]}.csv`);
        link.style.visibility = 'hidden';
        
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        this.addDebugLog('info', 'Path check results exported to CSV');
    }

    startJobMonitoring(jobId) {
        this.currentJobId = jobId;
        this.lastProcessedHost = null; // Reset for new job

        // Show progress section
        document.getElementById('uploadSection').style.display = 'none';
        document.getElementById('progressSection').style.display = 'block';
        document.getElementById('resultsSection').style.display = 'none';

        // Set initial job info
        document.getElementById('jobId').textContent = `Job ID: ${jobId}`;
        document.getElementById('jobStatus').textContent = 'RUNNING';
        document.getElementById('jobStatus').className = 'job-status';
        document.getElementById('progressText').textContent = '0 / 0 hosts processed';
        document.getElementById('progressPercent').textContent = '0%';
        document.getElementById('progressFill').style.width = '0%';
        document.getElementById('currentHost').textContent = 'Starting scan...';

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
        // Log the received update for debugging
        if (this.verboseMode) {
            console.log('[WebSocket Update]', data);
        }
        
        // Update progress regardless of message type
        if (data.status || data.completed_hosts !== undefined) {
            this.updateProgress(data);
        }
        
        // Handle specific message types
        if (data.type === 'progress') {
            this.updateProgress(data);
        } else if (data.type === 'completed' || data.status === 'completed') {
            this.handleJobCompleted(data);
        } else if (data.type === 'error' || data.status === 'failed') {
            this.handleJobError(data);
        }
    }

    updateProgress(data) {
        let { completed_hosts = 0, total_hosts = 0, current_host } = data;
        completed_hosts = Number(completed_hosts) || 0;
        total_hosts = Number(total_hosts) || 0;
        const failed_hosts = Number(data.failed_hosts ?? 0) || 0;
        const processed_hosts = total_hosts > 0
            ? Math.min(completed_hosts + failed_hosts, total_hosts)
            : completed_hosts + failed_hosts;

        // Update progress text and bar
        const statusParts = [`${processed_hosts} / ${total_hosts} hosts processed`];
        const detailParts = [`✓ ${completed_hosts}`];
        if (failed_hosts > 0) {
            detailParts.push(`✗ ${failed_hosts}`);
        }
        statusParts.push(`(${detailParts.join(', ')})`);
        document.getElementById('progressText').textContent = statusParts.join(' ');

        const percent = total_hosts > 0 ? Math.round((processed_hosts / total_hosts) * 100) : 0;
        document.getElementById('progressPercent').textContent = `${percent}%`;
        document.getElementById('progressFill').style.width = `${percent}%`;

        // Update current host display and log only when host changes
        if (current_host) {
            document.getElementById('currentHost').textContent = `Scanning: ${current_host}`;
            
            if (current_host !== this.lastProcessedHost) {
                this.lastProcessedHost = current_host;
                const summary = `Processed ${processed_hosts}/${total_hosts} hosts (✓${completed_hosts}` +
                    (failed_hosts ? `, ✗${failed_hosts}` : '') + ')';
                this.addDebugLog('info', `${summary} - Active host: ${current_host}`, true);

                const shouldLogSummary = processed_hosts > 0 &&
                    (processed_hosts % 5 === 0 || processed_hosts === total_hosts);
                if (shouldLogSummary) {
                    this.addDebugLog('info', `Progress: ${processed_hosts}/${total_hosts} hosts processed (${percent}%)`, false);
                }
            }
        } else if (processed_hosts === total_hosts && total_hosts > 0) {
            document.getElementById('currentHost').textContent = 'All hosts processed';
            this.addDebugLog('info', `Scan complete: ${processed_hosts}/${total_hosts} hosts processed`, false);
        }

        // Update summary cards if results section is visible
        if (document.getElementById('resultsSection').style.display !== 'none') {
            document.getElementById('completedHosts').textContent = completed_hosts;
            document.getElementById('failedHosts').textContent = failed_hosts;
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
        
        // Reload audit history
        await this.loadAuditHistory();
        
        // If this was a rerun, automatically show differences
        if (this.parentJobId) {
            await this.showDifferences(this.currentJobId, this.parentJobId);
            this.parentJobId = null; // Clear after showing
        }
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

        // Populate results table with aggregated counts per host/path
        const tableBody = document.getElementById('resultsTableBody');
        tableBody.innerHTML = '';

        jobResult.results.forEach(hostResult => {
            const row = tableBody.insertRow();
            
            if (hostResult.users_with_access.length === 0) {
                // No users with access
                row.innerHTML = `
                    <td>${hostResult.hostname}</td>
                    <td>${hostResult.code_path}</td>
                    <td colspan="4" style="text-align: center; color: #6c757d;">
                        ${hostResult.error_message || 'No users with write access'}
                    </td>
                `;
            } else {
                // Count users by privilege type
                const ownerCount = hostResult.users_with_access.filter(u => u.privilege_type === 'owner').length;
                const groupCount = hostResult.users_with_access.filter(u => u.privilege_type === 'group').length;
                const sudoCount = hostResult.users_with_access.filter(u => u.privilege_type === 'sudo').length;
                const totalCount = hostResult.users_with_access.length;
                
                row.innerHTML = `
                    <td>${hostResult.hostname}</td>
                    <td>${hostResult.code_path}</td>
                    <td>${totalCount}</td>
                    <td>${ownerCount}</td>
                    <td>${groupCount}</td>
                    <td>${sudoCount}</td>
                `;
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

    async stopScan() {
        if (!this.currentJobId) {
            this.showError('No active scan to stop');
            return;
        }

        try {
            this.showLoading('Stopping scan...');
            
            const response = await fetch(`/api/v1/jobs/${this.currentJobId}/cancel`, {
                method: 'POST'
            });

            if (!response.ok) {
                throw new Error('Failed to stop scan');
            }

            // Close WebSocket
            if (this.websocket) {
                this.websocket.close();
            }

            document.getElementById('jobStatus').textContent = 'CANCELLED';
            document.getElementById('jobStatus').className = 'job-status failed';
            document.getElementById('currentHost').textContent = 'Scan stopped by user';

            this.hideLoading();
            this.addDebugLog('info', `Scan ${this.currentJobId} stopped by user`);

        } catch (error) {
            this.hideLoading();
            this.showError(`Failed to stop scan: ${error.message}`);
            this.addDebugLog('error', `Failed to stop scan: ${error.message}`);
        }
    }

    async stopAuditFromHistory(jobId) {
        try {
            this.showLoading('Stopping audit...');
            
            const response = await fetch(`/api/v1/jobs/${jobId}/cancel`, {
                method: 'POST'
            });

            if (!response.ok) {
                throw new Error('Failed to stop audit');
            }

            this.hideLoading();
            this.addDebugLog('info', `Audit ${jobId} stopped`);
            
            // Refresh audit history
            await this.loadAuditHistory();

        } catch (error) {
            this.hideLoading();
            this.showError(`Failed to stop audit: ${error.message}`);
            this.addDebugLog('error', `Failed to stop audit: ${error.message}`);
        }
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
            <input type="text" placeholder="Code path (e.g., /home/user)" class="paths-input">
            <button class="remove-button" onclick="this.parentElement.remove()">×</button>
        `;
        hostEntries.appendChild(entry);
    }

    clearDebugLogs() {
        this.debugLogBuffer = [];
        document.getElementById('debugLogs').innerHTML = '';
        this.addDebugLog('info', 'Debug logs cleared');
    }

    setDebugConsoleVisibility(isVisible) {
        this.debugConsoleVisible = isVisible;
        const debugConsole = document.getElementById('debugConsole');
        if (debugConsole) {
            debugConsole.style.display = isVisible ? 'block' : 'none';
        }

        const toggleButton = document.getElementById('debugToggleButton');
        if (toggleButton) {
            toggleButton.textContent = isVisible ? 'Hide Console' : 'Show Console';
            toggleButton.setAttribute('aria-pressed', isVisible ? 'true' : 'false');
        }
    }

    toggleDebugConsole() {
        this.setDebugConsoleVisibility(!this.debugConsoleVisible);
    }

    toggleVerboseMode() {
        this.verboseMode = !this.verboseMode;
        const button = document.getElementById('verboseButton');
        if (this.verboseMode) {
            button.classList.add('active');
            button.textContent = 'Verbose: ON';
            this.addDebugLog('info', 'Verbose mode enabled');
        } else {
            button.classList.remove('active');
            button.textContent = 'Verbose: OFF';
            this.addDebugLog('info', 'Verbose mode disabled');
        }
    }

    addDebugLog(level, message, verbose = false) {
        // Skip verbose messages if verbose mode is off
        if (verbose && !this.verboseMode) {
            return;
        }

        const timestamp = new Date().toLocaleTimeString();
        const logEntry = {
            timestamp,
            level,
            message,
            verbose,
            text: `[${timestamp}] ${level.toUpperCase()}: ${message}`
        };

        // Add to buffer
        this.debugLogBuffer.push(logEntry);
        
        // Trim buffer if too large
        if (this.debugLogBuffer.length > this.maxDebugLines) {
            this.debugLogBuffer = this.debugLogBuffer.slice(-this.maxDebugLines);
        }

        // Update display
        const debugLogs = document.getElementById('debugLogs');
        const logLine = document.createElement('div');
        logLine.className = `log-entry log-${level}`;
        if (verbose) {
            logLine.classList.add('log-verbose');
        }
        logLine.textContent = logEntry.text;
        debugLogs.appendChild(logLine);

        // Auto-scroll to bottom
        debugLogs.scrollTop = debugLogs.scrollHeight;

        // Also log to console for development
        if (this.verboseMode || !verbose) {
            console.log(`[CM-04 Scanner] ${logEntry.text}`);
        }
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

    // Audit History Management
    async loadAuditHistory() {
        try {
            const response = await fetch('/api/v1/audits');
            const data = await response.json();
            
            this.renderAuditList(data.audits || []);
        } catch (error) {
            console.error('Error loading audit history:', error);
        }
    }

    renderAuditList(audits) {
        const auditList = document.getElementById('auditList');
        
        if (audits.length === 0) {
            auditList.innerHTML = '<div class="audit-empty">No audits yet. Run your first scan to get started!</div>';
            return;
        }

        auditList.innerHTML = audits.map(audit => {
            const duration = audit.run_duration_seconds 
                ? this.formatDuration(audit.run_duration_seconds)
                : 'N/A';
            
            const createdDate = new Date(audit.created_at).toLocaleString();
            
            return `
                <div class="audit-item ${audit.status.toLowerCase()}" data-job-id="${audit.job_id}">
                    <div class="audit-item-header">
                        <span class="audit-run-number">${audit.run_number}</span>
                        <span class="audit-status ${audit.status.toLowerCase()}">${audit.status}</span>
                    </div>
                    <div class="audit-item-details">
                        <div><strong>${audit.job_name || 'Unnamed Audit'}</strong></div>
                        <div>📅 ${createdDate}</div>
                        <div>🖥️ ${audit.total_hosts} hosts</div>
                        <div>⏱️ Duration: ${duration}</div>
                        ${audit.status === 'completed' 
                            ? `<div>✓ ${audit.completed_hosts} completed, ✗ ${audit.failed_hosts} failed</div>`
                            : audit.status === 'running'
                            ? `<div>⏳ ${audit.completed_hosts} / ${audit.total_hosts} completed</div>`
                            : ''
                        }
                    </div>
                    <div class="audit-item-actions">
                        ${audit.status === 'completed' || audit.status === 'failed'
                            ? `<button class="audit-action-btn" onclick="rerunAudit('${audit.job_id}')">Rerun</button>
                               <button class="audit-action-btn" onclick="exportFailures('${audit.job_id}')">Export Failures</button>`
                            : audit.status === 'running'
                            ? `<button class="audit-action-btn" onclick="viewRunningAudit('${audit.job_id}')">View</button>
                               <button class="audit-action-btn stop" onclick="stopAuditFromHistory('${audit.job_id}')">Stop</button>`
                            : ''
                        }
                        ${audit.status === 'completed' || audit.status === 'failed'
                            ? `<button class="audit-action-btn archive" onclick="archiveAudit('${audit.job_id}')">Archive</button>`
                            : ''
                        }
                        <button class="audit-action-btn purge" onclick="purgeAudit('${audit.job_id}')">Purge</button>
                    </div>
                </div>
            `;
        }).join('');
    }

    formatDuration(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        
        if (hours > 0) {
            return `${hours}h ${minutes}m ${secs}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${secs}s`;
        } else {
            return `${secs}s`;
        }
    }

    async rerunAudit(jobId) {
        try {
            this.showLoading('Starting audit rerun...');
            
            const response = await fetch(`/api/v1/audits/${jobId}/rerun`, {
                method: 'POST'
            });
            
            if (!response.ok) {
                throw new Error('Failed to rerun audit');
            }
            
            const result = await response.json();
            this.hideLoading();
            
            this.addDebugLog('info', `Rerun started: ${result.job_id}`);
            
            // Start monitoring the new job
            this.startJobMonitoring(result.job_id);
            
            // Load audit history to show the new running job
            await this.loadAuditHistory();
            
            // If parent job exists, we'll compare after completion
            if (result.parent_job_id) {
                this.currentJobId = result.job_id;
                this.parentJobId = result.parent_job_id;
            }
            
        } catch (error) {
            this.hideLoading();
            this.showError(`Failed to rerun audit: ${error.message}`);
        }
    }

    async archiveAudit(jobId) {
        if (!confirm('Are you sure you want to archive this audit? It will be hidden but data will be preserved.')) {
            return;
        }
        
        try {
            const response = await fetch(`/api/v1/audits/${jobId}/archive`, {
                method: 'POST'
            });
            
            if (!response.ok) {
                throw new Error('Failed to archive audit');
            }
            
            this.addDebugLog('info', `Audit archived: ${jobId}`);
            await this.loadAuditHistory();
            
        } catch (error) {
            this.showError(`Failed to archive audit: ${error.message}`);
        }
    }

    async purgeAudit(jobId) {
        if (!confirm('Are you sure you want to permanently delete this audit? This cannot be undone.')) {
            return;
        }
        
        try {
            const response = await fetch(`/api/v1/audits/${jobId}/purge`, {
                method: 'DELETE'
            });
            
            if (!response.ok) {
                throw new Error('Failed to purge audit');
            }
            
            this.addDebugLog('info', `Audit purged: ${jobId}`);
            await this.loadAuditHistory();
            
        } catch (error) {
            this.showError(`Failed to purge audit: ${error.message}`);
        }
    }

    async viewRunningAudit(jobId) {
        this.currentJobId = jobId;
        this.startJobMonitoring(jobId);
        
        // Scroll to progress section
        document.getElementById('progressSection').scrollIntoView({ behavior: 'smooth' });
    }

    async showDifferences(currentJobId, previousJobId) {
        try {
            this.showLoading('Comparing audit results...');
            
            const response = await fetch(`/api/v1/audits/compare/${currentJobId}/${previousJobId}`);
            
            if (!response.ok) {
                throw new Error('Failed to compare audits');
            }
            
            const comparison = await response.json();
            this.hideLoading();
            
            this.renderDifferences(comparison);
            
        } catch (error) {
            this.hideLoading();
            this.showError(`Failed to compare audits: ${error.message}`);
        }
    }

    renderDifferences(comparison) {
        const differencesSection = document.getElementById('differencesSection');
        
        // Update summary
        document.getElementById('differencesAdded').textContent = comparison.summary.added || 0;
        document.getElementById('differencesRemoved').textContent = comparison.summary.removed || 0;
        document.getElementById('differencesModified').textContent = comparison.summary.modified || 0;
        document.getElementById('differencesTotal').textContent = comparison.summary.total_differences || 0;
        
        // Render differences table
        const tbody = document.getElementById('differencesTableBody');
        
        if (comparison.differences.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No differences found between the two audit runs.</td></tr>';
        } else {
            tbody.innerHTML = comparison.differences.map(diff => `
                <tr>
                    <td><span class="change-badge ${diff.change_type}">${diff.change_type}</span></td>
                    <td>${diff.hostname}</td>
                    <td>${diff.code_path}</td>
                    <td>${diff.user_id}</td>
                    <td>${diff.description}</td>
                </tr>
            `).join('');
        }
        
        // Store comparison for download
        this.currentComparison = comparison;
        
        // Show the differences section
        differencesSection.style.display = 'block';
        differencesSection.scrollIntoView({ behavior: 'smooth' });
    }

    downloadDifferences(format) {
        if (!this.currentComparison) {
            this.showError('No comparison data available');
            return;
        }
        
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        
        if (format === 'csv') {
            const csv = this.convertDifferencesToCSV(this.currentComparison.differences);
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `cm04_differences_${timestamp}.csv`;
            a.click();
            URL.revokeObjectURL(url);
        } else if (format === 'json') {
            const json = JSON.stringify(this.currentComparison, null, 2);
            const blob = new Blob([json], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `cm04_differences_${timestamp}.json`;
            a.click();
            URL.revokeObjectURL(url);
        }
    }

    convertDifferencesToCSV(differences) {
        const headers = ['Change Type', 'Hostname', 'Code Path', 'User ID', 'Description'];
        const rows = differences.map(diff => [
            diff.change_type,
            diff.hostname,
            diff.code_path,
            diff.user_id,
            diff.description
        ]);
        
        const csvContent = [
            headers.join(','),
            ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
        ].join('\n');
        
        return csvContent;
    }

    closeDifferences() {
        document.getElementById('differencesSection').style.display = 'none';
        this.currentComparison = null;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Global functions for inline event handlers
function refreshAuditHistory() {
    window.cm04Scanner.loadAuditHistory();
}

function rerunAudit(jobId) {
    window.cm04Scanner.rerunAudit(jobId);
}

function exportFailures(jobId) {
    // Download the failures CSV
    window.open(`/api/v1/jobs/${jobId}/export-failures`, '_blank');
}

function archiveAudit(jobId) {
    window.cm04Scanner.archiveAudit(jobId);
}

function purgeAudit(jobId) {
    window.cm04Scanner.purgeAudit(jobId);
}

function viewRunningAudit(jobId) {
    window.cm04Scanner.viewRunningAudit(jobId);
}

function downloadDifferences(format) {
    window.cm04Scanner.downloadDifferences(format);
}

function closeDifferences() {
    window.cm04Scanner.closeDifferences();
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

function toggleVerboseMode() {
    window.cm04Scanner.toggleVerboseMode();
}

function stopScan() {
    window.cm04Scanner.stopScan();
}

function stopAuditFromHistory(jobId) {
    window.cm04Scanner.stopAuditFromHistory(jobId);
}

function closeErrorModal() {
    window.cm04Scanner.closeErrorModal();
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    window.cm04Scanner = new CM04Scanner();
});
