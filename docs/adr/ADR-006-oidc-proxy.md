# ADR-006: Optional OIDC Proxy as a Perimeter Layer

**Status:** Accepted  
**Date:** 2026-09-17  
**Deciders:** careb36

---

## Context

[ADR-005](ADR-005-api-auth-and-single-instance.md) established static API keys
(the `X-API-Key` / `Bearer` header) as the *only* authentication mechanism for
the orchestrator API.  That design is intentional for a single-operator,
single-instance deployment where a pre-shared key is enough.

A follow-on requirement asked for a web-login experience (username + password,
session cookie, OIDC logout) in front of the orchestrator console, without
changing the key-based mechanism that automation clients already rely on.

## Decision

The optional `docker-compose.auth.yml` overlay adds two extra services to the
compose stack:

1. **Keycloak** (`--profile auth`) — an OIDC/OAuth2 identity provider.  It
   imports a realm definition from `auth/keycloak/realm.json`.  No demo users
   are shipped; operators must create their own accounts (see
   [Operations → Optional services](../operations.md#optional-services)).

2. **oauth2-proxy** (`--profile auth`) — an authentication reverse proxy that
   sits in front of the orchestrator.  It validates OIDC sessions (issued by
   Keycloak) before forwarding requests to `http://orchestrator:8000` on the
   Docker compose network.  The proxy listens on `${AUTH_PROXY_PORT:-8002}` on
   the host.

### What the overlay is NOT

- It does **not** replace API-key authentication.  Clients that already send
  `X-API-Key` continue to work unchanged; the proxy only intercepts browser
  sessions.
- It is **not** mandatory.  The base stack (`docker compose up`) works without
  it.  Port `127.0.0.1:8000` is still published on the host for direct access.
- It does **not** introduce a new authorisation model; access is "authenticated
  or rejected".  Fine-grained RBAC is out of scope.

### Networking

The overlay no longer uses `network_mode: host`.  `auth-proxy` joins the
default compose network and talks to the orchestrator by service name
(`http://orchestrator:8000`).  This means:

- The orchestrator container does **not** need to publish `8000` to the host
  for the proxy to reach it — but it *does* publish `127.0.0.1:8000` so that
  the base-stack quick-start (`curl http://localhost:8000/health`) keeps
  working.
- Keycloak is reachable from the browser at `http://localhost:${KEYCLOAK_PORT}`
  and from `auth-proxy` by the configured `OIDC_ISSUER_URL`.

## Browser access model

A browser cannot attach `X-API-Key` to its first navigation, and the OIDC
bearer token oauth2-proxy forwards is not an API key. So:

- `GET /console` and `GET /console/i18n.json` are **public**: they serve the
  console shell and its translations, which contain no target or run data.
  Every request the console then makes (`/runs`, `/targets`,
  `/analytics/...`, report and finding downloads) goes to the protected
  router with the key the operator types into the page (kept in
  `sessionStorage`, never in a cookie).
- With the auth overlay, the proxy authenticates the *person*; the API key
  still authenticates the *client*. Both apply — the console behind the
  proxy still asks for the key. Running the proxy with an empty
  `ORCHESTRATOR_API_KEY` turns the perimeter into the only control, which is
  acceptable only when the orchestrator port is not reachable except through
  the proxy (the compose file publishes `127.0.0.1:8000`, so on the host it
  is).
- The proxy does not inject the API key into upstream requests, by design:
  it would turn every authenticated browser session into a bearer of the
  shared key.

## Consequences

- Operators who want a login page add `docker-compose.auth.yml` to their
  `docker compose` command and configure the variables listed in `.env.example`
  under *Human authentication (optional — compose auth overlay)*.
- Operators must create at least one user in Keycloak after first start (UI at
  `http://localhost:${KEYCLOAK_PORT:-8085}`) — no demo credentials are shipped.
- ADR-005 remains the canonical record for the API-key mechanism; this ADR
  extends it with an *additive* perimeter, not a replacement.

## Links

- [ADR-005: Static API Keys, Structured Observability and a Single-Instance Deployment](ADR-005-api-auth-and-single-instance.md)
- [Operations — Optional services](../operations.md#optional-services)
