# Multi-stage production Dockerfile for PortFootprint CLI
FROM python:3.11-alpine AS builder

WORKDIR /app
RUN apk add --no-cache gcc musl-dev libffi-dev

COPY pyproject.toml requirements.txt README.md ./
COPY portfootprint/ ./portfootprint/

RUN pip install --no-cache-dir --user .

FROM python:3.11-alpine AS runner
WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /root/.local /root/.local
COPY --from=builder /app /app

ENV PATH=/root/.local/bin:$PATH
ENTRYPOINT ["portfootprint"]
