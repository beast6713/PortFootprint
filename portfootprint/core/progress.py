"""
Thread-safe ProgressTracker implementation for tracking scan status.
"""

import threading
from typing import Any, Callable, Optional


class ProgressTracker:
    """
    Coordinates status metrics across concurrent threads.
    Provides utility methods to track and retrieve scan state safely.
    """
    def __init__(self, total_tasks: int, on_step_callback: Optional[Callable[[], None]] = None) -> None:
        self.total_tasks = total_tasks
        self.completed_tasks = 0
        self.active_workers = 0
        self.on_step_callback = on_step_callback
        self._lock = threading.Lock()

    def start_task(self) -> None:
        """Indicates a worker thread has started processing a port."""
        with self._lock:
            self.active_workers += 1

    def complete_task(self) -> None:
        """Indicates a worker thread has completed processing a port."""
        with self._lock:
            self.completed_tasks += 1
            if self.active_workers > 0:
                self.active_workers -= 1
        if self.on_step_callback:
            self.on_step_callback()

    def get_progress_percentage(self) -> float:
        """Calculates current percentage of completed tasks."""
        with self._lock:
            if self.total_tasks <= 0:
                return 0.0
            return (self.completed_tasks / self.total_tasks) * 100.0

    def get_stats(self) -> dict[str, Any]:
        """Returns a snapshot dictionary of the current tracking status."""
        with self._lock:
            return {
                "total": self.total_tasks,
                "completed": self.completed_tasks,
                "active_workers": self.active_workers,
                "percent": (
                    (self.completed_tasks / self.total_tasks * 100.0)
                    if self.total_tasks > 0 else 0.0
                )
            }
