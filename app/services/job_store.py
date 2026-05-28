"""
In-memory job store for async verification tasks.

Each job tracks: status (queued|running|done|error), progress (0-100),
human-readable message, final result dict, and optional error string.

NOTE: This is intentionally simple for v1 (dev/single-instance).
For production with multiple replicas, replace with a DB-backed store
(e.g. a `verification_jobs` PostgreSQL table via SQLAlchemy).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from threading import Lock
from datetime import datetime, timezone


@dataclass
class JobState:
    status: str = "queued"  # queued | running | done | error
    progress: int = 0  # 0..100
    message: str = "Queued"
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class InMemoryJobStore:
    """Thread-safe in-memory store for verification job states."""

    def __init__(self):
        self._lock = Lock()
        self._jobs: Dict[str, JobState] = {}

    def create(self, job_id: str) -> None:
        """Register a new job in 'queued' state."""
        with self._lock:
            self._jobs[job_id] = JobState()

    def update(self, job_id: str, **kwargs) -> None:
        """
        Partial-update a job's fields.
        Accepted kwargs: status, progress, message, result, error.
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            for key, value in kwargs.items():
                if hasattr(job, key):
                    setattr(job, key, value)
            job.updated_at = datetime.now(timezone.utc).isoformat()

    def get(self, job_id: str) -> Optional[JobState]:
        """Return a snapshot of the job state, or None if not found."""
        with self._lock:
            return self._jobs.get(job_id)

    def delete(self, job_id: str) -> None:
        """Remove a completed job to free memory."""
        with self._lock:
            self._jobs.pop(job_id, None)


# Module-level singleton — imported by the router and verifier.
JOB_STORE = InMemoryJobStore()
