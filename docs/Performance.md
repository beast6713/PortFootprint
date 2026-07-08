# Performance Benchmarks & Scaling

This document details benchmarks, profiling parameters, and scaling guidelines.

## Baseline Statistics Metrics (Single Target Host)

| Scanned Ports | Concurrency Threads | Average Time | Ports / Second |
| ------------- | ------------------- | ------------ | -------------- |
| 100           | 20                  | ~1.1s        | ~90 p/s        |
| 500           | 50                  | ~2.2s        | ~220 p/s       |
| 1000          | 100                 | ~4.3s        | ~230 p/s       |
| 5000          | 200                 | ~18.5s       | ~270 p/s       |

## Performance Tuning
To improve execution speeds:
- **Decrease socket timeout (`--timeout 1.0`)**: Drastically reduces scan times on filtered ports.
- **Adjust concurrency threads (`--threads 100`)**: Under high concurrency threads, context switching overhead increases, but network latency decreases. Do not exceed `1000` threads.
- **Decrease retries (`--retries 0`)**: Improves execution speed at the cost of diagnostic reliability on congested networks.
