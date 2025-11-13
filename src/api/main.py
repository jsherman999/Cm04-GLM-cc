"""
FastAPI main application for CM-04 Scanner
Provides REST API endpoints for scanning and reporting
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
import uuid
import json
import logging
from typing import Dict, List, Optional, Set
import time

from ..config.settings import settings
from ..models.schemas import (
    ScanRequest, JobResult, JobStatus, JobProgress, HostScanResult,
    ApiError, HealthCheck, SSHConnectionInfo
)
from ..core.scanner import CM04Scanner
from ..core.report_generator import report_generator
from .websocket_manager import WebSocketManager


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global scanner instance
scanner = None
websocket_manager = WebSocketManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    global scanner

    # Startup
    logger.info("Starting CM-04 Scanner API")
    scanner = CM04Scanner()
    await scanner.initialize()
    logger.info("Scanner initialized successfully")

    yield

    # Shutdown
    logger.info("Shutting down CM-04 Scanner API")
    if scanner:
        await scanner.cleanup()
    logger.info("Scanner cleaned up successfully")


# Create FastAPI app
app = FastAPI(
    title="CM-04 Scanner API",
    description="API for scanning Linux host filesystem access controls",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/reports", StaticFiles(directory=settings.reports_dir), name="reports")


# API Routes
@app.get("/", response_class=FileResponse)
async def root():
    """Serve the main web interface"""
    return FileResponse("static/index.html")


@app.get("/health", response_model=HealthCheck)
async def health_check():
    """Health check endpoint"""
    try:
        ssh_connections = 100  # Maximum connections
        db_connected = True  # TODO: Implement actual DB health check

        return HealthCheck(
            status="healthy",
            version=settings.app_version,
            ssh_connections_available=ssh_connections,
            database_connected=db_connected
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")


@app.post("/api/v1/scan", response_model=Dict[str, str])
async def submit_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """Submit a new CM-04 scan job"""
    try:
        job_id = str(uuid.uuid4())

        # Submit scan job to background
        background_tasks.add_task(
            scanner.run_scan_job,
            job_id,
            request.hosts,
            request.job_name,
            request.tags
        )

        logger.info(f"Submitted scan job {job_id} with {len(request.hosts)} hosts")

        return {
            "job_id": job_id,
            "message": "Scan job submitted successfully",
            "status_url": f"/api/v1/jobs/{job_id}"
        }

    except Exception as e:
        logger.error(f"Error submitting scan job: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/scan/upload", response_model=Dict[str, str])
async def submit_scan_from_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    job_name: Optional[str] = None
):
    """Submit scan job from uploaded file"""
    try:
        # Validate file type
        if not file.filename.endswith(('.txt', '.csv', '.json')):
            raise HTTPException(
                status_code=400,
                detail="File must be .txt, .csv, or .json"
            )

        # Read file content
        content = await file.read()
        file_text = content.decode('utf-8')

        # Parse hosts from file
        hosts = scanner.parse_hosts_from_content(file_text, file.filename)

        if not hosts:
            raise HTTPException(
                status_code=400,
                detail="No valid hosts found in uploaded file"
            )

        job_id = str(uuid.uuid4())

        # Submit scan job
        background_tasks.add_task(
            scanner.run_scan_job,
            job_id,
            hosts,
            job_name or f"Upload: {file.filename}",
            ["file_upload"]
        )

        logger.info(f"Submitted scan job {job_id} from uploaded file {file.filename}")

        return {
            "job_id": job_id,
            "message": f"Scan job submitted successfully from {file.filename}",
            "hosts_count": len(hosts),
            "status_url": f"/api/v1/jobs/{job_id}"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing uploaded file: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/jobs/{job_id}", response_model=JobResult)
async def get_job(job_id: str):
    """Get job status and results"""
    try:
        job_result = scanner.get_job_result(job_id)
        if not job_result:
            raise HTTPException(status_code=404, detail="Job not found")
        return job_result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting job {job_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/jobs/{job_id}/progress")
async def get_job_progress(job_id: str):
    """Get job progress information"""
    try:
        progress = scanner.get_job_progress(job_id)
        if not progress:
            raise HTTPException(status_code=404, detail="Job not found")
        return progress
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting job progress {job_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/jobs")
async def list_jobs(
    status: Optional[JobStatus] = None,
    limit: int = 50,
    offset: int = 0
):
    """List recent jobs"""
    try:
        jobs = scanner.list_jobs(status_filter=status, limit=limit, offset=offset)
        return {"jobs": jobs, "total": len(jobs)}
    except Exception as e:
        logger.error(f"Error listing jobs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/v1/jobs/{job_id}")
async def cancel_job(job_id: str):
    """Cancel a running job"""
    try:
        success = scanner.cancel_job(job_id)
        if not success:
            raise HTTPException(status_code=404, detail="Job not found or cannot be cancelled")
        return {"message": "Job cancelled successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling job {job_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/audits")
async def get_audit_history(include_archived: bool = False):
    """Get audit history for the Completed Audits panel"""
    try:
        audits = scanner.get_audit_history(include_archived=include_archived)
        return {"audits": audits, "total": len(audits)}
    except Exception as e:
        logger.error(f"Error getting audit history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/audits/{job_id}/rerun")
async def rerun_audit(job_id: str, background_tasks: BackgroundTasks):
    """Rerun an existing audit"""
    try:
        new_job_id = await scanner.rerun_audit(job_id, compare_with_previous=True)
        return {
            "job_id": new_job_id,
            "parent_job_id": job_id,
            "message": "Audit rerun started successfully",
            "status_url": f"/api/v1/jobs/{new_job_id}"
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error rerunning audit {job_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/audits/{job_id}/archive")
async def archive_audit(job_id: str):
    """Archive an audit (hide from UI but keep in storage)"""
    try:
        success = scanner.archive_audit(job_id)
        if not success:
            raise HTTPException(status_code=404, detail="Audit not found")
        return {"message": "Audit archived successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error archiving audit {job_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/v1/audits/{job_id}/purge")
async def purge_audit(job_id: str):
    """Permanently delete an audit"""
    try:
        success = scanner.purge_audit(job_id)
        if not success:
            raise HTTPException(status_code=404, detail="Audit not found")
        return {"message": "Audit purged successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error purging audit {job_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/audits/compare/{current_job_id}/{previous_job_id}")
async def compare_audits(current_job_id: str, previous_job_id: str):
    """Compare two audit runs and get differences"""
    try:
        comparison = scanner.compare_audits(current_job_id, previous_job_id)
        return comparison
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error comparing audits: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/jobs/{job_id}/reports")
async def get_job_reports(job_id: str):
    """Get available reports for a job"""
    try:
        reports = scanner.get_job_reports(job_id)
        return {"reports": reports}
    except Exception as e:
        logger.error(f"Error getting reports for job {job_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/reports")
async def list_reports():
    """List all available reports"""
    try:
        reports = report_generator.get_report_list()
        return {"reports": reports}
    except Exception as e:
        logger.error(f"Error listing reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/jobs/{job_id}/reports/generate")
async def generate_job_reports(job_id: str, background_tasks: BackgroundTasks):
    """Generate all reports for a completed job"""
    try:
        job_result = scanner.get_job_result(job_id)
        if not job_result:
            raise HTTPException(status_code=404, detail="Job not found")

        if job_result.status != JobStatus.COMPLETED:
            raise HTTPException(
                status_code=400,
                detail="Reports can only be generated for completed jobs"
            )

        # Generate reports in background
        background_tasks.add_task(report_generator.generate_all_reports, job_result)

        return {"message": "Report generation started"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating reports for job {job_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.websocket("/ws/jobs/{job_id}")
async def websocket_job_updates(websocket: WebSocket, job_id: str):
    """WebSocket endpoint for real-time job updates"""
    await websocket_manager.connect(websocket, job_id)
    try:
        while True:
            # Send periodic updates
            progress = scanner.get_job_progress(job_id)
            if progress:
                await websocket_manager.send_json(websocket, progress.dict())

            # Sleep before next update
            await asyncio.sleep(2)

    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket, job_id)
    except Exception as e:
        logger.error(f"WebSocket error for job {job_id}: {e}")
        websocket_manager.disconnect(websocket, job_id)


@app.get("/api/v1/debug/logs")
async def get_debug_logs(hostname: Optional[str] = None, limit: int = 1000):
    """Get debug logs"""
    try:
        from ..core.ssh_engine import ssh_engine
        logs = ssh_engine.get_debug_logs(hostname=hostname, limit=limit)
        return {"logs": [log.dict() for log in logs]}
    except Exception as e:
        logger.error(f"Error getting debug logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/v1/debug/logs")
async def clear_debug_logs():
    """Clear debug logs"""
    try:
        from ..core.ssh_engine import ssh_engine
        ssh_engine.clear_debug_logs()
        return {"message": "Debug logs cleared"}
    except Exception as e:
        logger.error(f"Error clearing debug logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/test/ssh")
async def test_ssh_connection(conn_info: SSHConnectionInfo):
    """Test SSH connection to a host"""
    try:
        from ..core.ssh_engine import ssh_engine
        success = await ssh_engine.test_connection(conn_info)
        return {
            "hostname": conn_info.hostname,
            "connection_successful": success,
            "message": "Connection successful" if success else "Connection failed"
        }
    except Exception as e:
        logger.error(f"Error testing SSH connection to {conn_info.hostname}: {e}")
        return {
            "hostname": conn_info.hostname,
            "connection_successful": False,
            "message": str(e)
        }


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content=ApiError(error=exc.detail).dict()
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content=ApiError(error="Internal server error").dict()
    )


def start_server():
    """Entry point for cm04-server CLI command"""
    import click
    import uvicorn
    
    @click.command()
    @click.option('--host', default='0.0.0.0', help='Host to bind to')
    @click.option('--port', default=8000, type=int, help='Port to bind to')
    @click.option('--reload', is_flag=True, help='Enable auto-reload')
    def cli(host, port, reload):
        """Start CM-04 Scanner API server"""
        uvicorn.run(
            "src.api.main:app",
            host=host,
            port=port,
            reload=reload
        )
    
    cli()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.api.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )