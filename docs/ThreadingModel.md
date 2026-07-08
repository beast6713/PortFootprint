# Threading Model

This document describes the concurrency model and thread-safety details of **PortFootprint**.

## Thread Management
Concurrency is handled by Python's `concurrent.futures.ThreadPoolExecutor`.

- **Scheduler Control**: The thread pool is owned and managed inside `ScanScheduler` using a context manager to ensure safe thread cleanup.
- **Worker Isolation**: Each thread handles a distinct `ScanWorker` instance. Connect socket handles are created and closed inside local worker threads, preventing race conditions or socket sharing errors.

## Thread-Safe Aggregations
To prevent race conditions during parallel scan results logging:

- **Aggregator Mutex**: `ResultAggregator` uses a `threading.Lock()` to serialize appends to the internal result list.
- **Progress Synchronization**: `ProgressTracker` updates completions and active counters using a lock, ensuring carriage-return progress bars render accurately.

```
                  [ScanScheduler]
                         |
           +-------------+-------------+
           |             |             |
     (Thread 1)    (Thread 2)    (Thread 3)
         |             |             |
      [Worker]      [Worker]      [Worker]
         |             |             |
         +-------------+-------------+
                       |
                       v
             Mutex Lock Protection
                       |
              [ResultAggregator]
```
