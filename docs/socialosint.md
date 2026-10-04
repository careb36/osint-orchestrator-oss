# SocialOSINT Integration — Research & Design

> Written **before** implementation, as required.  
> Source: `bm-github/owasp-social-osint-agent` (MIT).

---

## 1. What the project is

OWASP SocialOSINT Agent is a Python 3.11 tool that fetches posts/profiles from
social media APIs and feeds them to an LLM (OpenAI-compatible) for natural-language
OSINT analysis. It ships **two interfaces sharing the same analysis engine**:

| Interface | Description |
| --- | --- |
| **CLI** | `python -m socialosintagent.main --stdin` — reads JSON from stdin, writes result to stdout |
| **Web server** | FastAPI app (`socialosintagent.web_server:app`) at port 8000, async REST API at `/api/v1/` |

---

## 2. Entry point (CLI)

```bash
python -m socialosintagent.main --stdin [--format json|markdown] [--no-auto-save]
```

| Flag | Default | Notes |
| --- | --- | --- |
| `--stdin` | off | Required for piped JSON mode |
| `--format json` | `markdown` | Returns JSON envelope instead of raw markdown |
| `--no-auto-save` | off | Skip writing output to `data/outputs/` |
| `--log-level` | `WARNING` | Progress/errors always go to stderr |

Exit codes: `0` = success, `1` = input/config error, `2` = completed with errors.

---

## 3. JSON input format (CLI and web API)

```json
{
  "platforms": {
    "twitter":    ["handle1", "handle2"],
    "reddit":     ["handle3"],
    "github":     ["handle4"],
    "bluesky":    ["handle5.bsky.social"],
    "mastodon":   ["handle6@mastodon.social"],
    "hackernews": ["handle7"]
  },
  "query": "Summarize main topics and analyze sentiment",
  "fetch_options": {
    "default_count": 50,
    "targets": {
      "twitter:handle1": { "count": 200 }
    }
  }
}
```

- `platforms` and `query` are **required**.
- Platforms without configured credentials are silently skipped (warning to stderr).
- `fetch_options` is optional; omitting it fetches 50 items per user by default.

---

## 4. JSON output format (CLI `--no-auto-save --format json`)

```json
{
  "success": true,
  "metadata": {
    "query": "Summarize main topics...",
    "targets": { "twitter": ["handle1"] },
    "generated_utc": "2024-09-08 17:53:06 UTC",
    "mode": "Online",
    "models": { "text": "gpt-4o", "image": "gpt-4o" },
    "fetch_stats": { "successful": 2, "failed": 0, "rate_limited": 0 },
    "vision_stats": { "total": 5, "analyzed": 5, "failed": 0, "skipped": 0 },
    "generation_time_seconds": 14.7
  },
  "report": "# OSINT Analysis Report\n\n**Query:** `...`\n\n## Twitter: @handle1\n..."
}
```

On error (exit code 1), stderr contains:

```json
{ "error": "Missing required fields", "missing_fields": ["query"] }
```

---

## 5. Web service REST API (`/api/v1/`)

The `web` service exposes a **full JSON REST API** (not just a UI):

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/v1/platforms` | List platforms available (credentials configured) |
| `POST` | `/api/v1/sessions` | Create a session (set targets/platforms) |
| `GET` | `/api/v1/sessions/{id}` | Get session including all query history |
| `POST` | `/api/v1/sessions/{id}/analyse` | Start async analysis job → `{"job_id": "..."}` |
| `GET` | `/api/v1/jobs/{job_id}` | Poll job status → `{"status": "complete", "query_id": "..."}` |
| `GET` | `/api/v1/sessions/{id}/export` | Full JSON export with report text |
| `GET` | `/api/v1/jobs/{job_id}/stream` | SSE stream of live progress events |

Interactive docs: `GET /api/docs` (Swagger), `GET /api/redoc`.

Optional HTTP Basic Auth via `OSINT_WEB_USER` / `OSINT_WEB_PASSWORD`.

---

## 6. Credentials per platform

| Platform | Env var(s) passed to SocialOSINT service | Required? |
| --- | --- | --- |
| Twitter/X | `TWITTER_BEARER_TOKEN` | Yes (mapped from `SOCIALOSINT_TWITTER_BEARER_TOKEN`) |
| Reddit | `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET`, `REDDIT_USER_AGENT` | Yes |
| GitHub | `GITHUB_TOKEN` | Optional (lower rate limit without) |
| Bluesky | `BLUESKY_IDENTIFIER`, `BLUESKY_APP_SECRET` | Yes |
| Mastodon | `MASTODON_INSTANCE_1_URL`, `MASTODON_INSTANCE_1_TOKEN`, `MASTODON_INSTANCE_1_DEFAULT=true` | Yes per instance |
| HackerNews | *(none)* | — |
| LLM | `LLM_API_KEY`, `LLM_API_BASE_URL`, `ANALYSIS_MODEL`, `IMAGE_ANALYSIS_MODEL` | **Required for all analysis** |

A platform without credentials is skipped by the service; `GET /api/v1/platforms` returns only configured platforms, which the orchestrator uses to filter the request before creating a session.

---

## 7. Package installation

**The project is NOT pip-installable.** There is no `pyproject.toml` or `setup.py`.
The only installation method is:

```bash
git clone https://github.com/bm-github/owasp-social-osint-agent
pip install -r requirements.txt          # core agent
pip install -r requirements-web.txt      # FastAPI + uvicorn for web server
```

System dependency: `libmagic1` (for file-type detection).

No pre-built Docker images are published to Docker Hub; images must be built
from source using the project's `Dockerfile.agent` or `Dockerfile.web`.

### Pinning the upstream version

`Dockerfile.socialosint` uses `ARG SOCIALOSINT_REF=afde7af56b212e33672f149a88caf55f718dfd5c` (pinned
`main` branch). For reproducible builds, override it with a full 40-character
commit SHA:

```bash
# Get the current HEAD SHA:
git ls-remote https://github.com/bm-github/owasp-social-osint-agent HEAD

# Build with a pinned SHA:
docker compose build --build-arg SOCIALOSINT_REF=<sha> socialosint
```

Update both `Dockerfile.socialosint` (the `ARG` default) and this section
when upgrading. The SHA is the single authoritative version reference.

---

## 8. Integration decision: HTTP web service

**Decision: use the HTTP web API** (`socialosint` Docker service built from source).

### Rationale

| Criterion | CLI subprocess | HTTP web API |
| --- | --- | --- |
| **Credential isolation** | Credentials must be in orchestrator container | ✅ Credentials only in `socialosint` service |
| **Process management** | Complex: timeout, stderr parsing, exit codes | ✅ Standard HTTP + timeout |
| **Platform availability check** | Parse stderr warnings | ✅ `GET /api/v1/platforms` returns list |
| **Pip-installable?** | ❌ Not a package — needs git clone + requirements.txt | N/A (separate service) |
| **Extras = socialosint** | Would need git dependency or bundled source | N/A |
| **Async compatibility** | Needs `asyncio.subprocess` | ✅ `httpx.AsyncClient` |
| **Reuse across runs** | Service must restart each time | ✅ Service stays running |

The main trade-off (service must be running before collector executes) is
acceptable because: the service is gated behind `--profile socialosint`; the
collector handles `httpx.ConnectError` and returns `CollectorResult(success=False)`
if the service is unavailable; and the orchestrator already assumes several
services (OpenCTI, SpiderFoot) are running.

### Resulting architecture

```text
orchestrator container ─── HTTP ──→ socialosint:8000 (built from source)
                                      │
                                      ├── POST /api/v1/sessions
                                      ├── POST /api/v1/sessions/{id}/analyse
                                      ├── GET  /api/v1/jobs/{job_id}  (poll)
                                      └── GET  /api/v1/sessions/{id}/export
```

---

## 9. STIX mapping

The **input** (platforms + usernames) drives observable creation — not the LLM
output, which is non-deterministic and goes to `CollectorResult.notes`.

| STIX object | How it is built |
| --- | --- |
| `user-account` | `account_type = platform`, `user_id = handle.lower()` — deterministic id |
| `url` | Profile URL constructed from platform + handle (see table below) |
| `relationship` (user-account → url) | `related-to` |
| `relationship` (user-account → domain-name of target) | `related-to` |
| Note | LLM analysis report — labelled "análisis de SocialOSINT, no verificado" |

**Profile URL construction:**

| Platform | URL pattern |
| --- | --- |
| twitter | `https://twitter.com/{handle}` |
| reddit | `https://reddit.com/u/{handle}` |
| github | `https://github.com/{handle}` |
| bluesky | `https://bsky.app/profile/{handle}` |
| mastodon | `https://{instance}/@{user}` (parsed from `user@instance` format) |
| hackernews | `https://news.ycombinator.com/user?id={handle}` |

Mastodon handles with no `@instance` suffix (just a username) get a URL only if
`SOCIALOSINT_MASTODON_INSTANCE_1_URL` is set; otherwise the URL is omitted (the
`user-account` observable is still created).

**Platform-specific numeric IDs** (Twitter user ID, Reddit fullname, etc.) are
NOT included in the STIX id — only the handle is, so the id is stable and
deterministic. If the platform API returns a numeric id, it is stored in
`x_opencti_description` as supplementary context.

---

## 10. Rate-limit policy

- One scan per target per orchestrator run.
- No automatic retries on HTTP 429 from platform APIs — the service logs a
  warning and the orchestrator surfaces it in `CollectorResult.notes`.
- The SocialOSINT service enforces its own per-platform rate limits internally.
