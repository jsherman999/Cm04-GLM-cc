"""
CM-04 Scanner - Main orchestration logic
Coordinates SSH operations, access analysis, and report generation
"""

import asyncio
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set
import json
import time
from dataclasses import dataclass

from .ssh_engine import ssh_engine, SSHConnectionInfo
from .access_analyzer import access_analyzer
from .report_generator import report_generator
from ..models.schemas import (
    HostInput, JobResult, JobStatus, JobProgress, HostScanResult,
    ScanRequest, AccessResult
)
from ..config.settings import settings


logger = logging.getLogger(__name__)


@dataclass
class JobState:
    """Internal job state representation"""
    job_id: str
    job_name: Optional[str]
    hosts: List[HostInput]
    status: JobStatus
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    results: List[HostScanResult]
    current_host_index: int
    total_hosts: int
    completed_hosts: int
    failed_hosts: int
    error_message: Optional[str]
    tags: Optional[List[str]]


class CM04Scanner:
    """Main CM-04 scanner class"""

    def __init__(self):
        self.jobs: Dict[str, JobState] = {}
        self.active_scans: Set[str] = set()
        self._initialized = False

    async def initialize(self):
        """Initialize scanner components"""
        if self._initialized:
            return

        logger.info("Initializing CM-04 scanner")
        # Initialize any required components
        self._initialized = True
        logger.info("CM-04 scanner initialized")

    async def cleanup(self):
        """Cleanup scanner resources"""
        logger.info("Cleaning up CM-04 scanner")

        # Cancel all active scans
        for job_id in list(self.active_scans):
            await self.cancel_job(job_id)

        # Cleanup SSH engine
        await ssh_engine.cleanup()

        # Clear caches
        access_analyzer.clear_cache()

        logger.info("CM-04 scanner cleaned up")

    async def run_scan_job(
        self,
        job_id: str,
        hosts: List[HostInput],
        job_name: Optional[str] = None,
        tags: Optional[List[str]] = None
    ):
        """Run a scan job on the specified hosts"""
        try:
            # Create job state
            job_state = JobState(
                job_id=job_id,
                job_name=job_name,
                hosts=hosts,
                status=JobStatus.PENDING,
                created_at=datetime.utcnow(),
                started_at=None,
                completed_at=None,
                results=[],
                current_host_index=0,
                total_hosts=len(hosts),
                completed_hosts=0,
                failed_hosts=0,
                error_message=None,
                tags=tags
            )

            self.jobs[job_id] = job_state
            self.active_scans.add(job_id)

            logger.info(f"Starting scan job {job_id} for {len(hosts)} hosts")

            # Mark job as running
            job_state.status = JobStatus.RUNNING
            job_state.started_at = datetime.utcnow()

            # Process hosts in batches
            await self._process_hosts(job_state)

            # Mark job as completed
            job_state.status = JobStatus.COMPLETED
            job_state.completed_at = datetime.utcnow()

            logger.info(f"Completed scan job {job_id}: {job_state.completed_hosts}/{job_state.total_hosts} hosts successful")

        except Exception as e:
            logger.error(f"Scan job {job_id} failed: {e}")
            if job_id in self.jobs:
                self.jobs[job_id].status = JobStatus.FAILED
                self.jobs[job_id].completed_at = datetime.utcnow()
                self.jobs[job_id].error_message = str(e)
        finally:
            self.active_scans.discard(job_id)

    async def _process_hosts(self, job_state: JobState):
        """Process all hosts for a job"""
        # Create batches for concurrent processing
        batch_size = 10  # Process 10 hosts concurrently
        for i in range(0, len(job_state.hosts), batch_size):
            batch = job_state.hosts[i:i + batch_size]

            # Process batch concurrently
            tasks = [
                self._process_host(job_state, host_input)
                for host_input in batch
            ]

            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for j, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Host processing failed: {result}")
                    job_state.failed_hosts += 1
                elif result:
                    job_state.results.append(result)
                    job_state.completed_hosts += 1
                else:
                    job_state.failed_hosts += 1

                job_state.current_host_index += 1

            # Small delay between batches
            await asyncio.sleep(0.1)

    async def _process_host(self, job_state: JobState, host_input: HostInput) -> Optional[HostScanResult]:
        """Process a single host and its code paths"""
        hostname = host_input.hostname
        logger.info(f"Processing host {hostname} (job {job_state.job_id})")

        try:
            # Create SSH connection info
            conn_info = SSHConnectionInfo(
                hostname=hostname,
                username=settings.ssh_user
            )

            # Test connection
            if not await ssh_engine.test_connection(conn_info):
                logger.error(f"Cannot connect to host {hostname}")
                return HostScanResult(
                    hostname=hostname,
                    code_path="",  # No specific path
                    users_with_access=[],
                    scan_timestamp=datetime.utcnow(),
                    error_message=f"SSH connection failed to {hostname}"
                )

            # Process each code path for this host
            all_access_results = []
            host_errors = []

            for code_path in host_input.code_paths:
                try:
                    # Analyze access using vastool for AD integration
                    access_results = await access_analyzer.analyze_path_via_vastool(
                        conn_info, code_path
                    )
                    all_access_results.extend(access_results)

                except Exception as e:
                    error_msg = f"Error analyzing path {code_path}: {str(e)}"
                    logger.error(f"{error_msg} on {hostname}")
                    host_errors.append(error_msg)

            # Create host scan result
            error_message = "; ".join(host_errors) if host_errors else None

            return HostScanResult(
                hostname=hostname,
                code_path=",".join(host_input.code_paths),  # All paths for this host
                users_with_access=all_access_results,
                scan_timestamp=datetime.utcnow(),
                error_message=error_message
            )

        except Exception as e:
            logger.error(f"Error processing host {hostname}: {e}")
            return HostScanResult(
                hostname=hostname,
                code_path="",
                users_with_access=[],
                scan_timestamp=datetime.utcnow(),
                error_message=str(e)
            )

    def get_job_result(self, job_id: str) -> Optional[JobResult]:
        """Get job results"""
        if job_id not in self.jobs:
            return None

        job_state = self.jobs[job_id]

        return JobResult(
            job_id=job_state.job_id,
            job_name=job_state.job_name,
            status=job_state.status,
            created_at=job_state.created_at,
            started_at=job_state.started_at,
            completed_at=job_state.completed_at,
            total_hosts=job_state.total_hosts,
            completed_hosts=job_state.completed_hosts,
            failed_hosts=job_state.failed_hosts,
            results=job_state.results,
            error_message=job_state.error_message
        )

    def get_job_progress(self, job_id: str) -> Optional[JobProgress]:
        """Get job progress"""
        if job_id not in self.jobs:
            return None

        job_state = self.jobs[job_id]
        current_host = None

        if job_state.current_host_index < len(job_state.hosts):
            current_host = job_state.hosts[job_state.current_host_index].hostname

        return JobProgress(
            job_id=job_state.job_id,
            status=job_state.status,
            completed_hosts=job_state.completed_hosts,
            total_hosts=job_state.total_hosts,
            current_host=current_host,
            error_message=job_state.error_message
        )

    def list_jobs(
        self,
        status_filter: Optional[JobStatus] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[JobResult]:
        """List jobs with optional status filter"""
        jobs = []

        for job_state in self.jobs.values():
            if status_filter and job_state.status != status_filter:
                continue

            jobs.append(self.get_job_result(job_state.job_id))

        # Sort by creation date (newest first)
        jobs.sort(key=lambda j: j.created_at, reverse=True)

        # Apply pagination
        return jobs[offset:offset + limit]

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running job"""
        if job_id not in self.jobs:
            return False

        job_state = self.jobs[job_id]

        if job_state.status not in [JobStatus.PENDING, JobStatus.RUNNING]:
            return False

        # Mark as cancelled
        job_state.status = JobStatus.CANCELLED
        job_state.completed_at = datetime.utcnow()

        # Remove from active scans
        self.active_scans.discard(job_id)

        logger.info(f"Cancelled job {job_id}")
        return True

    def get_job_reports(self, job_id: str) -> List[Dict[str, str]]:
        """Get available reports for a job"""
        if job_id not in self.jobs:
            return []

        job_state = self.jobs[job_id]

        if job_state.status != JobStatus.COMPLETED:
            return []

        # Look for existing report files
        reports = []
        reports_dir = settings.reports_dir

        for report_file in reports_dir.glob(f"*{job_id}*.csv"):
            reports.append({
                "type": "csv",
                "filename": report_file.name,
                "url": f"/reports/{report_file.name}"
            })

        for report_file in reports_dir.glob(f"*{job_id}*.json"):
            reports.append({
                "type": "json",
                "filename": report_file.name,
                "url": f"/reports/{report_file.name}"
            })

        for report_file in reports_dir.glob(f"*{job_id}*.html"):
            reports.append({
                "type": "html",
                "filename": report_file.name,
                "url": f"/reports/{report_file.name}"
            })

        return reports

    def parse_hosts_from_content(self, content: str, filename: str) -> List[HostInput]:
        """Parse hosts from uploaded file content"""
        hosts = []

        try:
            lines = content.strip().split('\n')

            if filename.endswith('.json'):
                # Parse JSON format
                data = json.loads(content)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            hostname = item.get('hostname') or item.get('host')
                            code_paths = item.get('code_paths', item.get('paths', []))
                            if hostname and code_paths:
                                hosts.append(HostInput(hostname=hostname, code_paths=code_paths))

            else:
                # Parse CSV/TSV/text format
                for line_num, line in enumerate(lines, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    if '\t' in line:
                        parts = line.split('\t')
                    elif ',' in line:
                        parts = line.split(',')
                    else:
                        parts = line.split()

                    if len(parts) >= 2:
                        hostname = parts[0].strip()
                        code_paths = [path.strip() for path in parts[1:] if path.strip()]
                        if code_paths:
                            hosts.append(HostInput(hostname=hostname, code_paths=code_paths))
                    elif len(parts) == 1:
                        # Default path if only hostname provided
                        hostname = parts[0].strip()
                        hosts.append(HostInput(hostname=hostname, code_paths=["/home", "/var"]))

        except Exception as e:
            logger.error(f"Error parsing hosts from {filename}: {e}")

        return hosts

    async def generate_reports_for_job(self, job_id: str) -> Dict[str, str]:
        """Generate all reports for a completed job"""
        job_result = self.get_job_result(job_id)
        if not job_result:
            raise ValueError(f"Job {job_id} not found")

        if job_result.status != JobStatus.COMPLETED:
            raise ValueError(f"Job {job_id} is not completed")

        reports = await report_generator.generate_all_reports(job_result)

        return {report_type: str(report_path) for report_type, report_path in reports.items()}

    def get_statistics(self) -> Dict[str, any]:
        """Get scanner statistics"""
        total_jobs = len(self.jobs)
        active_jobs = len(self.active_scans)

        completed_jobs = sum(
            1 for job in self.jobs.values()
            if job.status == JobStatus.COMPLETED
        )

        failed_jobs = sum(
            1 for job in self.jobs.values()
            if job.status == JobStatus.FAILED
        )

        total_hosts_scanned = sum(
            job.total_hosts for job in self.jobs.values()
        )

        return {
            "total_jobs": total_jobs,
            "active_jobs": active_jobs,
            "completed_jobs": completed_jobs,
            "failed_jobs": failed_jobs,
            "total_hosts_scanned": total_hosts_scanned,
            "success_rate": (
                (completed_jobs / total_jobs * 100) if total_jobs > 0 else 0
            )
        }