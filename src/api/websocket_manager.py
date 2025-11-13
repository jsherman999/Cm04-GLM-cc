"""
WebSocket manager for real-time job progress updates
"""

import json
import logging
from typing import Dict, Set
from fastapi import WebSocket, WebSocketDisconnect


logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages WebSocket connections for real-time updates"""

    def __init__(self):
        # Store active connections: {job_id: set of websockets}
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        # Store reverse lookup: websocket -> job_id
        self.connection_jobs: Dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, job_id: str):
        """Connect a websocket to a job for updates"""
        await websocket.accept()

        if job_id not in self.active_connections:
            self.active_connections[job_id] = set()

        self.active_connections[job_id].add(websocket)
        self.connection_jobs[websocket] = job_id

        logger.debug(f"WebSocket connected for job {job_id}")

    def disconnect(self, websocket: WebSocket, job_id: str):
        """Disconnect a websocket from a job"""
        if job_id in self.active_connections:
            self.active_connections[job_id].discard(websocket)

            # Clean up empty job entries
            if not self.active_connections[job_id]:
                del self.active_connections[job_id]

        if websocket in self.connection_jobs:
            del self.connection_jobs[websocket]

        logger.debug(f"WebSocket disconnected for job {job_id}")

    async def send_json(self, websocket: WebSocket, data: dict):
        """Send JSON data to a specific websocket"""
        try:
            await websocket.send_text(json.dumps(data))
        except Exception as e:
            logger.error(f"Error sending WebSocket message: {e}")

    async def broadcast_to_job(self, job_id: str, data: dict):
        """Broadcast data to all websockets connected to a job"""
        if job_id not in self.active_connections:
            return

        disconnected = set()
        for websocket in self.active_connections[job_id]:
            try:
                await websocket.send_text(json.dumps(data))
            except Exception as e:
                logger.error(f"Error broadcasting to WebSocket: {e}")
                disconnected.add(websocket)

        # Clean up disconnected websockets
        for websocket in disconnected:
            self.active_connections[job_id].discard(websocket)
            if websocket in self.connection_jobs:
                del self.connection_jobs[websocket]

        logger.debug(f"Broadcasted update to {len(self.active_connections[job_id])} clients for job {job_id}")

    async def broadcast_job_progress(self, job_id: str, progress_data: dict):
        """Broadcast job progress updates"""
        await self.broadcast_to_job(job_id, {
            "type": "progress",
            "job_id": job_id,
            **progress_data
        })

    async def broadcast_job_completed(self, job_id: str, result_data: dict):
        """Broadcast job completion notification"""
        await self.broadcast_to_job(job_id, {
            "type": "completed",
            "job_id": job_id,
            **result_data
        })

    async def broadcast_job_error(self, job_id: str, error_data: dict):
        """Broadcast job error notification"""
        await self.broadcast_to_job(job_id, {
            "type": "error",
            "job_id": job_id,
            **error_data
        })

    def get_connection_count(self, job_id: str) -> int:
        """Get number of active connections for a job"""
        return len(self.active_connections.get(job_id, set()))

    def get_all_connection_counts(self) -> Dict[str, int]:
        """Get connection counts for all jobs"""
        return {
            job_id: len(connections)
            for job_id, connections in self.active_connections.items()
        }