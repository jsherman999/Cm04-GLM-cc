#!/usr/bin/env python3
"""
CM-04 Scanner CLI - Submit scan jobs from command line
"""

import click
import json
import sys
import asyncio
import httpx
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

# Add the src directory to the path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.schemas import HostInput, ScanRequest


class CM04Client:
    """HTTP client for CM-04 Scanner API"""

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip('/')
        self.client = httpx.Client(timeout=60.0)

    def submit_scan(
        self,
        hosts: List[HostInput],
        job_name: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Submit a scan job"""
        scan_request = ScanRequest(
            hosts=hosts,
            job_name=job_name,
            tags=tags or []
        )

        response = self.client.post(
            f"{self.base_url}/api/v1/scan",
            json=scan_request.dict()
        )

        response.raise_for_status()
        return response.json()

    def submit_scan_from_file(
        self,
        file_path: Path,
        job_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Submit scan job from file"""
        with open(file_path, 'rb') as f:
            files = {'file': (file_path.name, f, 'application/octet-stream')}
            data = {}

            if job_name:
                data['job_name'] = job_name

            response = self.client.post(
                f"{self.base_url}/api/v1/scan/upload",
                files=files,
                data=data
            )

        response.raise_for_status()
        return response.json()

    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """Get job status"""
        response = self.client.get(f"{self.base_url}/api/v1/jobs/{job_id}")
        response.raise_for_status()
        return response.json()

    def get_job_progress(self, job_id: str) -> Dict[str, Any]:
        """Get job progress"""
        response = self.client.get(f"{self.base_url}/api/v1/jobs/{job_id}/progress")
        response.raise_for_status()
        return response.json()

    def cancel_job(self, job_id: str) -> Dict[str, Any]:
        """Cancel a job"""
        response = self.client.delete(f"{self.base_url}/api/v1/jobs/{job_id}")
        response.raise_for_status()
        return response.json()

    def list_jobs(
        self,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """List jobs"""
        params = {'limit': limit, 'offset': offset}
        if status:
            params['status'] = status

        response = self.client.get(f"{self.base_url}/api/v1/jobs", params=params)
        response.raise_for_status()
        return response.json()

    def download_report(self, report_url: str, output_path: Path):
        """Download a report"""
        response = self.client.get(f"{self.base_url}{report_url}")
        response.raise_for_status()

        with open(output_path, 'wb') as f:
            f.write(response.content)

    def test_connection(self) -> bool:
        """Test connection to the API"""
        try:
            response = self.client.get(f"{self.base_url}/health")
            return response.status_code == 200
        except Exception:
            return False


def parse_hosts_file(file_path: Path) -> List[HostInput]:
    """Parse hosts from various file formats"""
    hosts = []

    if file_path.suffix.lower() == '.json':
        # Parse JSON format
        with open(file_path) as f:
            data = json.load(f)

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    hostname = item.get('hostname') or item.get('host')
                    code_paths = item.get('code_paths', item.get('paths', []))
                    if hostname and code_paths:
                        hosts.append(HostInput(hostname=hostname, code_paths=code_paths))

    else:
        # Parse CSV/TSV/text format
        with open(file_path) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Try different delimiters
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
                    # Default paths if only hostname provided
                    hostname = parts[0].strip()
                    hosts.append(HostInput(hostname=hostname, code_paths=["/home", "/var"]))

    return hosts


@click.group()
@click.option('--api-url', default='http://localhost:8000', help='CM-04 Scanner API URL')
@click.pass_context
def cli(ctx, api_url):
    """CM-04 Scanner CLI Tool"""
    ctx.ensure_object(dict)
    ctx.obj['client'] = CM04Client(api_url)


@cli.command()
@click.pass_context
def test(ctx):
    """Test connection to CM-04 Scanner API"""
    client = ctx.obj['client']

    if client.test_connection():
        click.echo("✅ Connection to CM-04 Scanner API successful")
    else:
        click.echo("❌ Failed to connect to CM-04 Scanner API", err=True)
        sys.exit(1)


@cli.command()
@click.option('--hostname', '-h', required=True, help='Hostname to scan')
@click.option('--paths', '-p', required=True, help='Code paths to analyze (comma-separated)')
@click.option('--job-name', '-n', help='Optional job name')
@click.option('--tags', '-t', help='Optional job tags (comma-separated)')
@click.pass_context
def scan(ctx, hostname, paths, job_name, tags):
    """Submit scan for a single host"""
    client = ctx.obj['client']

    try:
        code_paths = [path.strip() for path in paths.split(',') if path.strip()]
        tag_list = [tag.strip() for tag in tags.split(',')] if tags else None

        hosts = [HostInput(hostname=hostname, code_paths=code_paths)]

        click.echo(f"Submitting scan for {hostname} with paths: {', '.join(code_paths)}")

        result = client.submit_scan(hosts, job_name, tag_list)

        click.echo(f"✅ Scan job submitted successfully")
        click.echo(f"Job ID: {result['job_id']}")
        click.echo(f"Status URL: {result['status_url']}")

        return result['job_id']

    except Exception as e:
        click.echo(f"❌ Failed to submit scan: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--job-name', '-n', help='Optional job name')
@click.pass_context
def scan_file(ctx, file_path, job_name):
    """Submit scan from file"""
    client = ctx.obj['client']
    file_obj = Path(file_path)

    try:
        click.echo(f"Submitting scan from file: {file_obj}")

        result = client.submit_scan_from_file(file_obj, job_name)

        click.echo(f"✅ Scan job submitted successfully")
        click.echo(f"Job ID: {result['job_id']}")
        if 'hosts_count' in result:
            click.echo(f"Hosts to scan: {result['hosts_count']}")
        click.echo(f"Status URL: {result['status_url']}")

        return result['job_id']

    except Exception as e:
        click.echo(f"❌ Failed to submit scan from file: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('job_id')
@click.option('--watch', '-w', is_flag=True, help='Watch progress in real-time')
@click.option('--interval', '-i', default=5, help='Polling interval in seconds (default: 5)')
@click.pass_context
def status(ctx, job_id, watch, interval):
    """Get job status"""
    client = ctx.obj['client']

    def print_status(status_data):
        click.echo(f"\nJob ID: {status_data['job_id']}")
        if status_data.get('job_name'):
            click.echo(f"Job Name: {status_data['job_name']}")
        click.echo(f"Status: {status_data['status'].upper()}")
        click.echo(f"Created: {status_data['created_at']}")
        if status_data.get('started_at'):
            click.echo(f"Started: {status_data['started_at']}")
        if status_data.get('completed_at'):
            click.echo(f"Completed: {status_data['completed_at']}")
        click.echo(f"Progress: {status_data['completed_hosts']}/{status_data['total_hosts']} hosts")
        click.echo(f"Failed: {status_data['failed_hosts']}")

        if status_data.get('error_message'):
            click.echo(f"Error: {status_data['error_message']}")

    try:
        if watch:
            click.echo(f"Watching job {job_id} (Ctrl+C to stop)...")
            while True:
                status_data = client.get_job_progress(job_id)
                click.clear()
                print_status(status_data)

                if status_data['status'] in ['completed', 'failed', 'cancelled']:
                    click.echo(f"\nJob {status_data['status'].upper()}")
                    break

                import time
                time.sleep(interval)
        else:
            status_data = client.get_job_status(job_id)
            print_status(status_data)

    except Exception as e:
        click.echo(f"❌ Failed to get job status: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('job_id')
@click.pass_context
def cancel(ctx, job_id):
    """Cancel a running job"""
    client = ctx.obj['client']

    try:
        click.echo(f"Cancelling job {job_id}...")

        result = client.cancel_job(job_id)

        click.echo(f"✅ Job cancelled successfully")

    except Exception as e:
        click.echo(f"❌ Failed to cancel job: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--status', '-s', help='Filter by status')
@click.option('--limit', '-l', default=20, help='Number of jobs to list (default: 20)')
@click.pass_context
def list(ctx, status, limit):
    """List recent jobs"""
    client = ctx.obj['client']

    try:
        result = client.list_jobs(status=status, limit=limit)

        if not result['jobs']:
            click.echo("No jobs found")
            return

        click.echo(f"{'Job ID':<36} {'Status':<12} {'Created':<20} {'Job Name':<20} {'Progress':<15}")
        click.echo("-" * 105)

        for job in result['jobs']:
            job_id = job['job_id'][:8] + "..."
            created = datetime.fromisoformat(job['created_at']).strftime('%Y-%m-%d %H:%M:%S')
            job_name = (job.get('job_name') or '-')[:17]
            if len(job.get('job_name') or '') > 17:
                job_name = job_name[:14] + "..."

            progress = f"{job['completed_hosts']}/{job['total_hosts']}"

            click.echo(f"{job_id:<36} {job['status']:<12} {created:<20} {job_name:<20} {progress:<15}")

        click.echo(f"\nTotal: {result['total']} jobs")

    except Exception as e:
        click.echo(f"❌ Failed to list jobs: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('job_id')
@click.option('--format', '-f', type=click.Choice(['csv', 'json', 'html']), default='csv', help='Report format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--open', is_flag=True, help='Open HTML report in browser')
@click.pass_context
def report(ctx, job_id, format, output, open):
    """Generate and download job report"""
    client = ctx.obj['client']

    try:
        # First generate reports
        click.echo(f"Generating reports for job {job_id}...")
        generate_response = client.client.post(f"{client.base_url}/api/v1/jobs/{job_id}/reports/generate")
        generate_response.raise_for_status()

        # Wait a moment for report generation
        import time
        time.sleep(2)

        # Get available reports
        reports_response = client.client.get(f"{client.base_url}/api/v1/jobs/{job_id}/reports")
        reports_response.raise_for_status()
        reports_data = reports_response.json()

        report_info = next((r for r in reports_data['reports'] if r['type'] == format), None)
        if not report_info:
            click.echo(f"❌ {format.upper()} report not found for job {job_id}", err=True)
            sys.exit(1)

        # Determine output path
        if not output:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output = Path(f"cm04_report_{job_id}_{timestamp}.{format}")

        output_path = Path(output)

        # Download report
        click.echo(f"Downloading {format.upper()} report...")
        client.download_report(report_info['url'], output_path)

        click.echo(f"✅ Report downloaded to: {output_path}")

        # Open HTML report if requested
        if format == 'html' and open:
            import webbrowser
            webbrowser.open(f"file://{output_path.absolute()}")

    except Exception as e:
        click.echo(f"❌ Failed to generate/download report: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('job_id')
@click.option('--output', '-o', type=click.Path(), help='Output CSV file path')
@click.pass_context
def export(ctx, job_id, output):
    """Export job results to CSV"""
    client = ctx.obj['client']

    try:
        # Get job results
        job_result = client.get_job_status(job_id)

        if job_result['status'] != 'completed':
            click.echo(f"❌ Job {job_id} is not completed (status: {job_result['status']})", err=True)
            sys.exit(1)

        # Generate CSV content
        import csv
        import io

        if not output:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path(f"cm04_export_{job_id}_{timestamp}.csv")
        else:
            output_path = Path(output)

        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['hostname', 'code_path', 'user_id', 'login_method', 'privilege_type', 'priv_granting_access']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for host_result in job_result['results']:
                for access in host_result['users_with_access']:
                    writer.writerow({
                        'hostname': host_result['hostname'],
                        'code_path': host_result['code_path'],
                        'user_id': access['user_id'],
                        'login_method': access['login_method'],
                        'privilege_type': access['privilege_type'],
                        'priv_granting_access': access['privilege_source']
                    })

        click.echo(f"✅ Results exported to: {output_path}")
        click.echo(f"Total records: {len(open(output_path).readlines()) - 1}")

    except Exception as e:
        click.echo(f"❌ Failed to export results: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()