# OWASP Amass v5 CLI clients (oam_enum / oam_subs). They are static binaries
# built with CGO_ENABLED=0, so they run unchanged on the Debian base below.
# The Amass *engine* itself runs as a separate compose service (profile
# "amass"); the orchestrator only needs the two clients that talk to it.
FROM owaspamass/amass:v5.1.1 AS amass

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

COPY --from=amass /bin/enum /usr/local/bin/oam_enum
COPY --from=amass /bin/subs /usr/local/bin/oam_subs

# Create directories for runtime data. /app/amass/data is the mount point of
# the volume shared with the Amass engine container, which runs as uid 1000:
# pre-own it so the engine can write asset.db whichever container initialises
# the volume first.
RUN mkdir -p /app/daily_reports /app/data /app/amass/data \
    && chown 1000:1000 /app/amass/data

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "orchestrator.api:app", "--host", "0.0.0.0", "--port", "8000"]
