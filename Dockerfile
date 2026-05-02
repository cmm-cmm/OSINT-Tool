# ── OSINT Tool — Docker image ─────────────────────────────────────────────────
# Multi-stage build: keeps final image lean (~200 MB)
#
# Build:   docker build -t osint-tool .
# Run TUI: docker run --rm -it osint-tool menu
# Run CLI: docker run --rm -it osint-tool whois example.com

FROM python:3.12-slim AS base

# System deps: git (for update cmd), curl (internet check), nmap (optional scans)
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        git curl wget ca-certificates \
        build-essential libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/osint-tool

# ── Install Python deps first (layer cache friendly) ─────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ── Copy source ───────────────────────────────────────────────────────────────
COPY . .

# ── Create non-root user ──────────────────────────────────────────────────────
RUN useradd -m -s /bin/bash osint && \
    chown -R osint:osint /opt/osint-tool
USER osint

# ── Runtime ───────────────────────────────────────────────────────────────────
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TERM=xterm-256color

ENTRYPOINT ["python", "osint.py"]
CMD ["menu"]
