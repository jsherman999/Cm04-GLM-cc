"""
Report Generator for CM-04 Scanner
Generates CSV reports and other output formats
"""

import csv
import json
import asyncio
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

from ..models.schemas import HostScanResult, JobResult, AccessResult
from ..config.settings import settings


logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates CM-04 compliance reports in various formats"""

    def __init__(self):
        self.reports_dir = Path(settings.reports_dir)
        self.reports_dir.mkdir(exist_ok=True)

    def generate_csv_report(self, job_result: JobResult) -> Path:
        """
        Generate CSV report with the required format:
        hostname, user_id, login_method, priv_granting_access, access_method, enabled
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cm04_report_{job_result.job_id}_{timestamp}.csv"
        filepath = self.reports_dir / filename

        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'hostname',
                    'code_path',
                    'user_id',
                    'login_method',
                    'privilege_type',
                    'priv_granting_access',
                    'access_method',
                    'enabled',
                    'scan_timestamp'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                # Write header
                writer.writeheader()

                # Write data rows
                for host_result in job_result.results:
                    for access in host_result.users_with_access:
                        writer.writerow({
                            'hostname': host_result.hostname,
                            'code_path': host_result.code_path,
                            'user_id': access.user_id,
                            'login_method': access.login_method.value,
                            'privilege_type': access.privilege_type.value,
                            'priv_granting_access': access.privilege_source,
                            'access_method': access.access_method,
                            'enabled': access.enabled,
                            'scan_timestamp': host_result.scan_timestamp.isoformat()
                        })

            logger.info(f"CSV report generated: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
            raise

    def generate_summary_report(self, job_result: JobResult) -> Dict[str, Any]:
        """Generate summary statistics for the scan"""
        summary = {
            "job_id": job_result.job_id,
            "job_name": job_result.job_name,
            "scan_date": job_result.created_at.isoformat(),
            "status": job_result.status.value,
            "total_hosts": job_result.total_hosts,
            "completed_hosts": job_result.completed_hosts,
            "failed_hosts": job_result.failed_hosts,
            "success_rate": (
                (job_result.completed_hosts / job_result.total_hosts * 100)
                if job_result.total_hosts > 0 else 0
            )
        }

        # Analyze access patterns
        total_users_with_access = 0
        access_by_privilege_type = {}
        access_by_login_method = {}
        host_access_summary = []

        for host_result in job_result.results:
            users_count = len(host_result.users_with_access)
            total_users_with_access += users_count

            # Count by privilege type for this host
            owner_count = 0
            group_count = 0
            sudo_count = 0

            # Count by privilege type
            for access in host_result.users_with_access:
                priv_type = access.privilege_type.value
                login_method = access.login_method.value

                access_by_privilege_type[priv_type] = access_by_privilege_type.get(priv_type, 0) + 1
                access_by_login_method[login_method] = access_by_login_method.get(login_method, 0) + 1

                # Count for this host
                if priv_type == 'owner':
                    owner_count += 1
                elif priv_type == 'group':
                    group_count += 1
                elif priv_type == 'sudo':
                    sudo_count += 1

            # Host summary
            host_access_summary.append({
                "hostname": host_result.hostname,
                "code_path": host_result.code_path,
                "users_with_access": users_count,
                "owner_access": owner_count,
                "group_access": group_count,
                "sudo_access": sudo_count,
                "has_error": host_result.error_message is not None
            })

        summary.update({
            "total_users_with_access": total_users_with_access,
            "average_users_per_host": (
                total_users_with_access / job_result.completed_hosts
                if job_result.completed_hosts > 0 else 0
            ),
            "access_by_privilege_type": access_by_privilege_type,
            "access_by_login_method": access_by_login_method,
            "host_access_summary": host_access_summary
        })

        return summary

    def generate_json_report(self, job_result: JobResult) -> Path:
        """Generate detailed JSON report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cm04_report_{job_result.job_id}_{timestamp}.json"
        filepath = self.reports_dir / filename

        try:
            report_data = {
                "metadata": {
                    "job_id": job_result.job_id,
                    "job_name": job_result.job_name,
                    "generated_at": datetime.now().isoformat(),
                    "generator_version": "1.0.0"
                },
                "summary": self.generate_summary_report(job_result),
                "results": []
            }

            for host_result in job_result.results:
                host_data = {
                    "hostname": host_result.hostname,
                    "code_path": host_result.code_path,
                    "scan_timestamp": host_result.scan_timestamp.isoformat(),
                    "users_with_access": [
                        {
                            "user_id": access.user_id,
                            "login_method": access.login_method.value,
                            "privilege_type": access.privilege_type.value,
                            "privilege_source": access.privilege_source
                        }
                        for access in host_result.users_with_access
                    ],
                    "error_message": host_result.error_message
                }
                report_data["results"].append(host_data)

            with open(filepath, 'w', encoding='utf-8') as jsonfile:
                json.dump(report_data, jsonfile, indent=2, ensure_ascii=False)

            logger.info(f"JSON report generated: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            raise

    def generate_compliance_matrix(self, job_result: JobResult) -> Path:
        """
        Generate a compliance matrix showing which hosts have users with elevated access
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cm04_compliance_matrix_{job_result.job_id}_{timestamp}.csv"
        filepath = self.reports_dir / filename

        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'hostname',
                    'code_path',
                    'total_users_with_access',
                    'users_with_owner_access',
                    'users_with_sudo_access',
                    'users_with_group_access',
                    'local_users',
                    'domain_users',
                    'compliance_status'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for host_result in job_result.results:
                    if host_result.error_message:
                        compliance_status = "ERROR"
                    else:
                        # Define compliance criteria (can be customized)
                        users_with_sudo = len([
                            a for a in host_result.users_with_access
                            if a.privilege_type.value == "sudo"
                        ])

                        # More than 5 users with sudo access might be non-compliant
                        if users_with_sudo > 5:
                            compliance_status = "NON_COMPLIANT"
                        else:
                            compliance_status = "COMPLIANT"

                    users_with_owner = len([
                        a for a in host_result.users_with_access
                        if a.privilege_type.value == "owner"
                    ])
                    users_with_sudo = len([
                        a for a in host_result.users_with_access
                        if a.privilege_type.value == "sudo"
                    ])
                    users_with_group = len([
                        a for a in host_result.users_with_access
                        if a.privilege_type.value == "group"
                    ])
                    local_users = len([
                        a for a in host_result.users_with_access
                        if a.login_method.value == "local"
                    ])
                    domain_users = len([
                        a for a in host_result.users_with_access
                        if a.login_method.value == "domain"
                    ])

                    writer.writerow({
                        'hostname': host_result.hostname,
                        'code_path': host_result.code_path,
                        'total_users_with_access': len(host_result.users_with_access),
                        'users_with_owner_access': users_with_owner,
                        'users_with_sudo_access': users_with_sudo,
                        'users_with_group_access': users_with_group,
                        'local_users': local_users,
                        'domain_users': domain_users,
                        'compliance_status': compliance_status
                    })

            logger.info(f"Compliance matrix generated: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error generating compliance matrix: {e}")
            raise

    def generate_html_report(self, job_result: JobResult) -> Path:
        """Generate HTML report with styling and charts"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cm04_report_{job_result.job_id}_{timestamp}.html"
        filepath = self.reports_dir / filename

        try:
            summary = self.generate_summary_report(job_result)

            html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>CM-04 Compliance Report - {job_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f8f9fa; }}
        .header {{ background-color: #667eea; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0 0 10px 0; }}
        .header p {{ margin: 5px 0; opacity: 0.9; }}
        .summary {{ display: flex; flex-wrap: wrap; gap: 20px; margin: 20px 0; }}
        .metric {{ background-color: white; padding: 15px; border-radius: 5px; min-width: 150px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .metric h3 {{ margin: 0 0 10px 0; color: #495057; font-size: 14px; }}
        .metric .value {{ font-size: 24px; font-weight: bold; color: #007bff; }}
        .actions {{ margin: 20px 0; }}
        .btn {{ 
            background-color: #667eea; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 5px; 
            cursor: pointer; 
            font-size: 14px;
            margin-right: 10px;
        }}
        .btn:hover {{ background-color: #5568d3; }}
        .btn-danger {{ background-color: #dc3545; }}
        .btn-danger:hover {{ background-color: #c82333; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background-color: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        th, td {{ border: 1px solid #ddd; padding: 12px 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; font-weight: 600; }}
        tr:hover {{ background-color: #f8f9fa; }}
        .host-unreachable {{ background-color: #f8d7da; color: #721c24; }}
        .host-unreachable td {{ border-color: #f5c6cb; }}
        .path-not-found {{ color: #721c24; font-weight: 600; }}
        .path-world-writable {{ color: #004085; font-weight: 600; background-color: #cce5ff; padding: 2px 6px; border-radius: 3px; }}
        .compliant {{ background-color: #d4edda; }}
        .error {{ background-color: #fff3cd; }}
        .status-ok {{ color: #28a745; font-weight: 600; }}
        .status-error {{ color: #dc3545; font-weight: 600; }}
        .legend {{ margin: 20px 0; padding: 15px; background-color: white; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .legend h3 {{ margin: 0 0 10px 0; }}
        .legend-item {{ display: inline-block; margin-right: 20px; margin-bottom: 10px; }}
        .legend-color {{ display: inline-block; width: 20px; height: 20px; margin-right: 5px; vertical-align: middle; border: 1px solid #ddd; }}
    </style>
    <script>
        function exportFailures() {{
            const jobId = "{job_id}";
            window.location.href = `/api/v1/jobs/${{jobId}}/export-failures`;
        }}
        
        function downloadCSV() {{
            const jobId = "{job_id}";
            window.location.href = `/reports/cm04_report_${{jobId}}_*?.csv`;
        }}
    </script>
</head>
<body>
    <div class="header">
        <h1>CM-04 Compliance Report</h1>
        <p><strong>Job ID:</strong> {job_id}</p>
        <p><strong>Job Name:</strong> {job_name}</p>
        <p><strong>Generated:</strong> {generated_time}</p>
    </div>

    <div class="actions">
        <button class="btn btn-danger" onclick="exportFailures()">Export Failures (CSV)</button>
        <button class="btn" onclick="downloadCSV()">Download Full Report (CSV)</button>
    </div>

    <div class="legend">
        <h3>Legend</h3>
        <div class="legend-item">
            <span class="legend-color" style="background-color: #f8d7da;"></span>
            <span>Host Unreachable (entire row red)</span>
        </div>
        <div class="legend-item">
            <span class="legend-color" style="background-color: white; color: #721c24; font-weight: bold;">P</span>
            <span>Path Does Not Exist (path in red)</span>
        </div>
        <div class="legend-item">
            <span class="legend-color" style="background-color: #cce5ff;"></span>
            <span>Path World-Writable (path in blue, not a failure)</span>
        </div>
    </div>

    <div class="summary">
        <div class="metric">
            <h3>Total Hosts</h3>
            <div class="value">{total_hosts}</div>
        </div>
        <div class="metric">
            <h3>Completed</h3>
            <div class="value">{completed_hosts}</div>
        </div>
        <div class="metric">
            <h3>Failed</h3>
            <div class="value">{failed_hosts}</div>
        </div>
        <div class="metric">
            <h3>Success Rate</h3>
            <div class="value">{success_rate:.1f}%</div>
        </div>
        <div class="metric">
            <h3>Total Users with Access</h3>
            <div class="value">{total_users}</div>
        </div>
    </div>

    <h2>Host Access Summary</h2>
    <table>
        <thead>
            <tr>
                <th>Hostname</th>
                <th>Code Path</th>
                <th>Users with Access</th>
                <th>Owner Access</th>
                <th>Sudo Access</th>
                <th>Group Access</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {host_rows}
        </tbody>
    </table>

    <h2>Access Distribution</h2>
    <div class="summary">
        <div class="metric">
            <h3>Owner Access</h3>
            <div class="value">{owner_access}</div>
        </div>
        <div class="metric">
            <h3>Sudo Access</h3>
            <div class="value">{sudo_access}</div>
        </div>
        <div class="metric">
            <h3>Group Access</h3>
            <div class="value">{group_access}</div>
        </div>
        <div class="metric">
            <h3>Local Users</h3>
            <div class="value">{local_users}</div>
        </div>
        <div class="metric">
            <h3>Domain Users</h3>
            <div class="value">{domain_users}</div>
        </div>
    </div>
</body>
</html>
            """

            # Generate host rows with enhanced error detection
            host_rows = ""
            for host_result in job_result.results:
                # Determine failure type from error_message
                is_host_unreachable = False
                is_path_not_found = False
                is_world_writable = False
                
                if host_result.error_message:
                    error_lower = host_result.error_message.lower()
                    if "cannot connect" in error_lower or "ssh connection" in error_lower or "unreachable" in error_lower:
                        is_host_unreachable = True
                    elif "path does not exist" in error_lower or "no such file" in error_lower:
                        is_path_not_found = True
                    elif "world" in error_lower and "writable" in error_lower:
                        is_world_writable = True
                
                # Set row class
                row_class = ""
                if is_host_unreachable:
                    row_class = "host-unreachable"
                
                # Format path with appropriate styling
                path_display = host_result.code_path
                if is_path_not_found:
                    path_display = f'<span class="path-not-found">{host_result.code_path}</span>'
                elif is_world_writable:
                    path_display = f'<span class="path-world-writable">{host_result.code_path}</span>'
                
                # Format status
                if host_result.error_message:
                    if is_host_unreachable:
                        status_display = '<span class="status-error">HOST UNREACHABLE</span>'
                    elif is_path_not_found:
                        status_display = '<span class="status-error">PATH NOT FOUND</span>'
                    elif is_world_writable:
                        status_display = '<span class="status-ok">WORLD WRITABLE</span>'
                    else:
                        status_display = '<span class="status-error">ERROR</span>'
                else:
                    status_display = '<span class="status-ok">OK</span>'
                
                # Count access types
                users_count = len(host_result.users_with_access)
                owner_count = len([a for a in host_result.users_with_access if a.privilege_type.value == "owner"])
                sudo_count = len([a for a in host_result.users_with_access if a.privilege_type.value == "sudo"])
                group_count = len([a for a in host_result.users_with_access if a.privilege_type.value == "group"])

                host_rows += f"""
                <tr class="{row_class}">
                    <td>{host_result.hostname}</td>
                    <td>{path_display}</td>
                    <td>{users_count}</td>
                    <td>{owner_count}</td>
                    <td>{sudo_count}</td>
                    <td>{group_count}</td>
                    <td>{status_display}</td>
                </tr>
                """

            html_content = html_template.format(
                job_id=job_result.job_id,
                job_name=job_result.job_name or "Unnamed",
                generated_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total_hosts=summary["total_hosts"],
                completed_hosts=summary["completed_hosts"],
                failed_hosts=summary["failed_hosts"],
                success_rate=summary["success_rate"],
                total_users=summary["total_users_with_access"],
                host_rows=host_rows,
                owner_access=summary["access_by_privilege_type"].get("owner", 0),
                sudo_access=summary["access_by_privilege_type"].get("sudo", 0),
                group_access=summary["access_by_privilege_type"].get("group", 0),
                local_users=summary["access_by_login_method"].get("local", 0),
                domain_users=summary["access_by_login_method"].get("domain", 0)
            )

            with open(filepath, 'w', encoding='utf-8') as htmlfile:
                htmlfile.write(html_content)

            logger.info(f"HTML report generated: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            raise

    def generate_failures_csv(self, job_result: JobResult) -> Path:
        """
        Generate CSV report of only failures (host unreachable, path does not exist)
        Format: hostname,path,failure_reason
        Note: World-writable paths are NOT considered failures
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cm04_failures_{job_result.job_id}_{timestamp}.csv"
        filepath = self.reports_dir / filename

        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['hostname', 'path', 'failure_reason']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                # Write header
                writer.writeheader()

                # Write failure rows
                for host_result in job_result.results:
                    if host_result.error_message:
                        error_lower = host_result.error_message.lower()
                        
                        # Check for host unreachable
                        if "cannot connect" in error_lower or "ssh connection" in error_lower or "unreachable" in error_lower:
                            # Split paths if multiple paths in code_path field
                            paths = [p.strip() for p in host_result.code_path.split(',') if p.strip()]
                            for path in paths:
                                writer.writerow({
                                    'hostname': host_result.hostname,
                                    'path': path,
                                    'failure_reason': 'host unreachable'
                                })
                        
                        # Check for path does not exist
                        elif "path does not exist" in error_lower or "no such file" in error_lower:
                            # Split paths if multiple paths in code_path field
                            paths = [p.strip() for p in host_result.code_path.split(',') if p.strip()]
                            for path in paths:
                                writer.writerow({
                                    'hostname': host_result.hostname,
                                    'path': path,
                                    'failure_reason': 'path does not exist'
                                })
                        
                        # Skip world-writable (not a failure)
                        # Any other error types can be added here if needed

            logger.info(f"Failures CSV generated: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error generating failures CSV: {e}")
            raise

    async def generate_all_reports(self, job_result: JobResult) -> Dict[str, Path]:
        """Generate all report formats"""
        try:
            reports = {}

            # Generate CSV report
            reports["csv"] = self.generate_csv_report(job_result)

            # Generate JSON report
            reports["json"] = self.generate_json_report(job_result)

            # Generate HTML report
            reports["html"] = self.generate_html_report(job_result)

            # Generate compliance matrix
            reports["compliance_matrix"] = self.generate_compliance_matrix(job_result)

            logger.info(f"All reports generated for job {job_result.job_id}")
            return reports

        except Exception as e:
            logger.error(f"Error generating reports for job {job_result.job_id}: {e}")
            raise

    def get_report_list(self) -> List[Dict[str, Any]]:
        """Get list of available reports"""
        reports = []

        try:
            for filepath in self.reports_dir.glob("*.csv"):
                stat = filepath.stat()
                reports.append({
                    "filename": filepath.name,
                    "type": "csv",
                    "size": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "download_url": f"/reports/{filepath.name}"
                })

            for filepath in self.reports_dir.glob("*.json"):
                stat = filepath.stat()
                reports.append({
                    "filename": filepath.name,
                    "type": "json",
                    "size": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "download_url": f"/reports/{filepath.name}"
                })

            for filepath in self.reports_dir.glob("*.html"):
                stat = filepath.stat()
                reports.append({
                    "filename": filepath.name,
                    "type": "html",
                    "size": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "download_url": f"/reports/{filepath.name}"
                })

            # Sort by creation date (newest first)
            reports.sort(key=lambda x: x["created_at"], reverse=True)

            return reports

        except Exception as e:
            logger.error(f"Error getting report list: {e}")
            return []

    def cleanup_old_reports(self, days_old: int = 30):
        """Clean up reports older than specified days"""
        try:
            cutoff_time = datetime.now().timestamp() - (days_old * 24 * 60 * 60)

            deleted_count = 0
            for filepath in self.reports_dir.iterdir():
                if filepath.is_file() and filepath.stat().st_ctime < cutoff_time:
                    filepath.unlink()
                    deleted_count += 1

            logger.info(f"Cleaned up {deleted_count} old reports older than {days_old} days")

        except Exception as e:
            logger.error(f"Error cleaning up old reports: {e}")


# Global report generator instance
report_generator = ReportGenerator()