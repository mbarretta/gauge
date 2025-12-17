# Use Chainguard's Python base image (minimal, distroless-style)
FROM cgr.dev/chainguard/python:latest-dev AS builder

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Multi-stage build: use runtime image with Docker CLI and scanning tools
FROM cgr.dev/chainguard/python:latest-dev

WORKDIR /app

USER root

# Install Docker CLI, syft, and grype for vulnerability scanning
# Versions pinned per infosec recommendation
RUN apk add --no-cache \
    docker-cli=29.1.3-r0 \
    syft=1.38.2-r0 \
    grype=0.104.2-r0

# Copy installed packages from builder to root's local directory
COPY --from=builder /home/nonroot/.local /root/.local

# Copy application code
COPY src/ ./src/

# Set PATH to include user-installed packages and PYTHONPATH for module imports
ENV PATH="/root/.local/bin:${PATH}"
ENV PYTHONPATH="/app/src"

# Mount point for Docker socket (needed for CHPS scanning)
VOLUME /var/run/docker.sock

# Default entrypoint
ENTRYPOINT ["python", "-m", "cli"]
