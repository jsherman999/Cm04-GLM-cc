#!/usr/bin/env python3
"""
CM-04 Scanner Monitor - Real-time job monitoring utility
"""

import click
import sys
import time
import httpx
from pathlib import Path
from typing import Optional
from datetime import datetime
import threading

# Add the src directory to the path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.cm04_scan import CM04Client


class JobMonitor:
    """Real-time job monitoring utility"""

    def __init__(self, client: CM04Client):
        self.client = client
        self.stop_monitoring = False
        self.show_details = False

    def monitor_job(self, job_id: str, interval: int = 5, detailed: bool = False):
        """Monitor a job in real-time"""
        self.show_details = detailed
        self.stop_monitoring = False

        click.echo(f"Monitoring job {job_id} (Press Ctrl+C to stop)")
        click.echo("=" * 80)

        try:
            while not self.stop_monitoring:
                try:
                    progress_data = self.client.get_job_progress(job_id)
                    self.display_progress(progress_data)

                    if progress_data['status'] in ['completed', 'failed', 'cancelled']:
                        self.display_completion(progress_data)
                        break

                    time.sleep(interval)

                except KeyboardInterrupt:
                    click.echo("\n\nMonitoring stopped by user")
                    break
                except Exception as e:
                    click.echo(f"Error monitoring job: {e}")
                    time.sleep(interval)

        except Exception as e:
            click.echo(f"❌ Failed to monitor job: {e}", err=True)
            sys.exit(1)

    def display_progress(self, progress_data: dict):
        """Display current progress"""
        # Clear screen and show updated progress
        click.clear()

        # Header
        click.echo(f"🔍 CM-04 Scanner Job Monitor")
        click.echo("=" * 80)
        click.echo(f"Job ID: {progress_data['job_id']}")
        click.echo(f"Status: {self.get_status_emoji(progress_data['status'])} {progress_data['status'].upper()}")
        click.echo(f"Progress: {progress_data['completed_hosts']}/{progress_data['total_hosts']} hosts "
                   f"({self.get_percentage(progress_data)}%)")
        click.echo(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Progress bar
        self.display_progress_bar(progress_data['completed_hosts'], progress_data['total_hosts'])

        # Current host
        if progress_data.get('current_host'):
            click.echo(f"📍 Currently Scanning: {progress_data['current_host']}")
        else:
            click.echo("📍 Currently Scanning: Initializing...")

        # Detailed information
        if self.show_details:
            self.display_detailed_info(progress_data)

        # Instructions
        click.echo("\n" + "─" * 80)
        click.echo("Press Ctrl+C to stop monitoring")

    def display_progress_bar(self, completed: int, total: int, width: int = 50):
        """Display an ASCII progress bar"""
        if total == 0:
            percentage = 0
        else:
            percentage = (completed / total) * 100

        filled_width = int(width * percentage / 100)
        bar = "█" * filled_width + "░" * (width - filled_width)

        click.echo(f"\n[{bar}] {percentage:.1f}%")

    def display_detailed_info(self, progress_data: dict):
        """Display detailed job information"""
        click.echo(f"\n📊 Detailed Information:")
        click.echo(f"   Completed Hosts: {progress_data['completed_hosts']}")
        click.echo(f"   Total Hosts: {progress_data['total_hosts']}")

        # Calculate estimated time remaining
        if progress_data['completed_hosts'] > 0 and progress_data['total_hosts'] > progress_data['completed_hosts']:
            remaining = progress_data['total_hosts'] - progress_data['completed_hosts']
            # Simple estimation: assume current rate continues
            click.echo(f"   Remaining Hosts: {remaining}")

        if progress_data.get('error_message'):
            click.echo(f"\n⚠️  Warning: {progress_data['error_message']}")

    def display_completion(self, progress_data: dict):
        """Display job completion information"""
        click.echo(f"\n🏁 Job {progress_data['status'].upper()}!")
        click.echo("=" * 80)

        if progress_data['status'] == 'completed':
            click.echo(f"✅ Successfully completed scan of {progress_data['total_hosts']} hosts")
            click.echo(f"   Completed: {progress_data['completed_hosts']} hosts")
            click.echo(f"   Failed: {progress_data.get('failed_hosts', 0)} hosts")

            # Show next steps
            click.echo(f"\n📋 Next Steps:")
            click.echo(f"   View results: cm04_scan status {progress_data['job_id']}")
            click.echo(f"   Download CSV: cm04_scan report {progress_data['job_id']} --format csv")
            click.echo(f"   View HTML: cm04_scan report {progress_data['job_id']} --format html --open")

        elif progress_data['status'] == 'failed':
            click.echo(f"❌ Job failed!")
            if progress_data.get('error_message'):
                click.echo(f"   Error: {progress_data['error_message']}")

        elif progress_data['status'] == 'cancelled':
            click.echo(f"⏹️  Job was cancelled")
            click.echo(f"   Progress: {progress_data['completed_hosts']}/{progress_data['total_hosts']} hosts")

    def get_status_emoji(self, status: str) -> str:
        """Get emoji for job status"""
        status_emojis = {
            'pending': '⏳',
            'running': '🔄',
            'completed': '✅',
            'failed': '❌',
            'cancelled': '⏹️'
        }
        return status_emojis.get(status, '❓')

    def get_percentage(self, progress_data: dict) -> float:
        """Calculate completion percentage"""
        if progress_data['total_hosts'] == 0:
            return 0.0
        return (progress_data['completed_hosts'] / progress_data['total_hosts']) * 100

    def monitor_multiple_jobs(self, job_ids: list, interval: int = 5):
        """Monitor multiple jobs simultaneously"""
        click.echo(f"Monitoring {len(job_ids)} jobs")
        click.echo("=" * 80)

        try:
            while not self.stop_monitoring:
                click.clear()
                click.echo(f"🔍 CM-04 Scanner Multi-Job Monitor")
                click.echo("=" * 80)
                click.echo(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                click.echo("")

                all_completed = True

                for i, job_id in enumerate(job_ids, 1):
                    try:
                        progress_data = self.client.get_job_progress(job_id)
                        self.display_job_summary(i, progress_data)

                        if progress_data['status'] in ['pending', 'running']:
                            all_completed = False

                    except Exception as e:
                        click.echo(f"{i}. Job {job_id}: ❌ Error - {e}")

                click.echo("\n" + "─" * 80)
                click.echo("Press Ctrl+C to stop monitoring")

                if all_completed:
                    click.echo("\n🏁 All jobs completed!")
                    break

                time.sleep(interval)

        except KeyboardInterrupt:
            click.echo("\n\nMonitoring stopped by user")

    def display_job_summary(self, index: int, progress_data: dict):
        """Display summary for a single job in multi-job view"""
        status_emoji = self.get_status_emoji(progress_data['status'])
        percentage = self.get_percentage(progress_data)

        click.echo(f"{index}. {status_emoji} Job {progress_data['job_id'][:8]}... - "
                   f"{progress_data['status'].upper()} ({percentage:.1f}%)")

        # Mini progress bar
        completed = progress_data['completed_hosts']
        total = progress_data['total_hosts']
        bar_width = 30
        if total > 0:
            filled_width = int(bar_width * completed / total)
            bar = "█" * filled_width + "░" * (bar_width - filled_width)
            click.echo(f"   [{bar}] {completed}/{total}")

        if progress_data.get('current_host'):
            click.echo(f"   📍 {progress_data['current_host']}")

        click.echo("")


@click.group()
@click.option('--api-url', default='http://localhost:8000', help='CM-04 Scanner API URL')
@click.pass_context
def cli(ctx, api_url):
    """CM-04 Scanner Monitor - Real-time job monitoring"""
    ctx.ensure_object(dict)
    ctx.obj['client'] = CM04Client(api_url)


@cli.command()
@click.argument('job_id')
@click.option('--interval', '-i', default=5, help='Polling interval in seconds (default: 5)')
@click.option('--detailed', '-d', is_flag=True, help='Show detailed information')
@click.pass_context
def job(ctx, job_id, interval, detailed):
    """Monitor a single job"""
    client = ctx.obj['client']
    monitor = JobMonitor(client)
    monitor.monitor_job(job_id, interval, detailed)


@cli.command()
@click.argument('job_ids', nargs=-1, required=True)
@click.option('--interval', '-i', default=5, help='Polling interval in seconds (default: 5)')
@click.pass_context
def jobs(ctx, job_ids, interval):
    """Monitor multiple jobs"""
    client = ctx.obj['client']
    monitor = JobMonitor(client)
    monitor.monitor_multiple_jobs(list(job_ids), interval)


@cli.command()
@click.option('--status', '-s', help='Filter by status')
@click.option('--limit', '-l', default=10, help='Number of recent jobs to monitor (default: 10)')
@click.option('--interval', '-i', default=5, help='Polling interval in seconds (default: 5)')
@click.pass_context
def recent(ctx, status, limit, interval):
    """Monitor recent jobs"""
    client = ctx.obj['client']

    try:
        # Get recent jobs
        result = client.list_jobs(status=status, limit=limit)
        jobs = result['jobs']

        if not jobs:
            click.echo("No recent jobs found")
            return

        job_ids = [job['job_id'] for job in jobs]
        click.echo(f"Monitoring {len(job_ids)} recent jobs")

        monitor = JobMonitor(client)
        monitor.monitor_multiple_jobs(job_ids, interval)

    except Exception as e:
        click.echo(f"❌ Failed to get recent jobs: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def active(ctx):
    """Monitor all active jobs"""
    client = ctx.obj['client']

    try:
        # Get all running jobs
        result = client.list_jobs(status='running', limit=100)
        jobs = result['jobs']

        # Also get pending jobs
        pending_result = client.list_jobs(status='pending', limit=100)
        jobs.extend(pending_result['jobs'])

        if not jobs:
            click.echo("No active jobs found")
            return

        job_ids = [job['job_id'] for job in jobs]
        click.echo(f"Monitoring {len(job_ids)} active jobs")

        monitor = JobMonitor(client)
        monitor.monitor_multiple_jobs(job_ids)

    except Exception as e:
        click.echo(f"❌ Failed to get active jobs: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('job_id')
@click.pass_context
def watch(ctx, job_id):
    """Quick watch a job with default settings"""
    client = ctx.obj['client']
    monitor = JobMonitor(client)
    monitor.monitor_job(job_id, interval=3, detailed=False)


@cli.command()
@click.pass_context
def dashboard(ctx):
    """Show a dashboard of all recent activity"""
    client = ctx.obj['client']

    try:
        while True:
            click.clear()
            click.echo("📊 CM-04 Scanner Dashboard")
            click.echo("=" * 80)
            click.echo(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            click.echo("")

            # Get job statistics
            stats = {}
            for status in ['pending', 'running', 'completed', 'failed', 'cancelled']:
                result = client.list_jobs(status=status, limit=100)
                stats[status] = len(result['jobs'])

            # Display statistics
            click.echo("📈 Job Statistics:")
            click.echo(f"   ⏳ Pending: {stats['pending']}")
            click.echo(f"   🔄 Running: {stats['running']}")
            click.echo(f"   ✅ Completed: {stats['completed']}")
            click.echo(f"   ❌ Failed: {stats['failed']}")
            click.echo(f"   ⏹️  Cancelled: {stats['cancelled']}")
            click.echo(f"   📊 Total: {sum(stats.values())}")

            # Show active jobs
            if stats['running'] > 0 or stats['pending'] > 0:
                click.echo(f"\n🔄 Active Jobs:")
                for status in ['running', 'pending']:
                    if stats[status] > 0:
                        result = client.list_jobs(status=status, limit=5)
                        for job in result['jobs']:
                            job_id = job['job_id'][:8]
                            progress = f"{job['completed_hosts']}/{job['total_hosts']}"
                            click.echo(f"   {status.upper()}: {job_id}... ({progress})")

            # Show recent failures
            if stats['failed'] > 0:
                click.echo(f"\n❌ Recent Failures:")
                result = client.list_jobs(status='failed', limit=3)
                for job in result['jobs']:
                    job_id = job['job_id'][:8]
                    created = datetime.fromisoformat(job['created_at']).strftime('%H:%M:%S')
                    click.echo(f"   {job_id}... at {created}")

            click.echo("\n" + "─" * 80)
            click.echo("Press Ctrl+C to exit | Refreshing every 10 seconds")

            time.sleep(10)

    except KeyboardInterrupt:
        click.echo("\n\nDashboard closed by user")

    except Exception as e:
        click.echo(f"❌ Dashboard error: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()