# OWASP Amass v5 CLI clients (oam_enum / oam_subs). They are static binaries
# built with CGO_ENABLED=0, so they run unchanged on the Debian base below.
# The Amass *engine* itself runs as a separate compose service (profile
# "amass"); the orchestrator only needs the two clients that talk to it.
FROM owaspamass/amass:v5.1.1 AS amass

# React operator dashboard (ui/). Built here so the runtime image needs no
# Node: the output is static files the orchestrator serves under /console.
FROM node:22.12.0-alpine3.20 AS ui-builder
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/ ./
RUN npm run build

FROM python:3.11-slim

WORKDIR /app

# Install minimal system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # git: the openosint dependency is a pinned git reference, and pip
    # needs a git client to resolve it. python:3.11-slim ships without one.
    git \
    # libmagic1: pycti 6.x imports python-magic, which loads libmagic at import
    # time; without it the OpenCTI sink cannot be imported.
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# README.md and LICENSE are referenced from pyproject.toml (readme / license.file);
# hatchling refuses to build metadata without them.
COPY pyproject.toml README.md LICENSE ./
# Dummy package source so pip can resolve the project metadata
RUN mkdir -p orchestrator && touch orchestrator/__init__.py
# The llm extra brings the cloud provider SDKs (openai for openai/nebius,
# anthropic for anthropic); without it every cloud synthesis fails at runtime.
RUN pip install --no-cache-dir ".[llm]"

COPY orchestrator/ ./orchestrator/
# Dashboard build: orchestrator/api.py serves it at /console (and answers 503
# with the build steps when the directory is missing).
COPY --from=ui-builder /ui/dist ./orchestrator/static/ui-dist

COPY --from=amass /bin/enum /usr/local/bin/oam_enum
COPY --from=amass /bin/subs /usr/local/bin/oam_subs

# Create directories for runtime data. /app/amass/data is the mount point of
# the volume shared with the Amass engine container, which runs as uid 1000:
# pre-own it so the engine can write asset.db whichever container initialises
# the volume first.
# The service runs as uid 1000 (the same uid the Helm chart and the Amass
# engine use), never as root: a bug in a collector or in the PDF renderer
# must not get root inside the container. Everything the process writes at
# run time lives under these three directories.
RUN mkdir -p /app/daily_reports /app/data /app/amass/data \
    && groupadd --gid 1000 app \
    && useradd --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin app \
    && chown -R 1000:1000 /app/daily_reports /app/data /app/amass/data

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

USER 1000

CMD ["python", "-m", "uvicorn", "orchestrator.api:app", "--host", "0.0.0.0", "--port", "8000"]
