"""
ScanScheduler managing ThreadPoolExecutor tasks submission and shutdown controls.
"""

import concurrent.futures
import logging
from typing import Any, Optional

from portfootprint.core.exceptions import ScanExecutionError
from portfootprint.scanner.worker import ScanWorker

logger = logging.getLogger("portfootprint.scanner.scheduler")


class ScanScheduler:
    """
    Coordinates multi-threaded port scans.
    Submits port tasks to ThreadPoolExecutor and handles interrupts.
    """
    def __init__(self, threads: int) -> None:
        self.threads = threads
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._futures: dict[concurrent.futures.Future[Any], int] = {}

    def run(self, ports: list[int], worker: ScanWorker) -> None:
        """
        Launches threads and polls execution status.
        Supports cancellation under KeyboardInterrupt.
        """
        logger.debug(f"Configuring ThreadPoolExecutor with {self.threads} workers.")

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                self._executor = executor

                # Submit all tasks
                for port in ports:
                    future = executor.submit(worker.execute, port)
                    self._futures[future] = port

                # Wait for completion of all futures
                for future in concurrent.futures.as_completed(self._futures):
                    # We retrieve the result (or raise exception if worker crashed)
                    try:
                        future.result()
                    except Exception as e:
                        port = self._futures[future]
                        logger.exception(f"Worker for port {port} crashed: {e!s}")

        except KeyboardInterrupt:
            logger.warning("Scan run interrupted by user (Ctrl+C). Terminating workers...")
            self.cancel_all()
            raise
        except Exception as e:
            raise ScanExecutionError(f"Fatal scheduler executor error: {e!s}") from e
        finally:
            self._executor = None
            self._futures.clear()

    def cancel_all(self) -> None:
        """Cancels all active/pending worker threads."""
        logger.debug("Requesting cancellation of all running port tasks.")
        for future in self._futures:
            if not future.done():
                future.cancel()

        # Shutdown executor immediately without waiting for running threads to block
        if self._executor:
            # Python 3.9+ cancel_futures parameter check
            try:
                self._executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                # Fallback for Python 3.8
                self._executor.shutdown(wait=False)
