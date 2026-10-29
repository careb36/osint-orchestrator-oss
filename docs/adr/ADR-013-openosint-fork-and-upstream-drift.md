# ADR-013: OpenOSINT fork pin and upstream drift monitoring

**Date:** 2026-10-29  
**Status:** Accepted

## Context

Three dependency pins in this repository are invisible to Dependabot, because
none of them looks like a package version: OpenOSINT is a PEP 508 direct
reference to a git commit, SpiderFoot is a compose `build.context` pointing at
a repository, and SocialOSINT is an `ARG` inside a Dockerfile. Nothing in the
repository said when those moved.

OpenOSINT is pinned at the fork `careb36/OpenOSINT`, not at the upstream
`OpenOSINT/OpenOSINT`. The fork carries `openosint/investigate.py` and
`InvestigationBudget`, the stable Python entry point the collector imports
(`orchestrator/collectors/openosint.py`). Upstream does not ship that module:
its programmatic entry point is a different async API (`investigate_graph`
in `openosint/pivot.py`, added in 2.35/2.36) with a different signature. The
proposal to adopt a stable API upstream (issue #52) is still open with no
response, and the fork has diverged (at the time of writing, 161 commits behind
upstream and 23 ahead).

## Decision

1. **Keep the fork pin** for OpenOSINT as long as `investigate()` lives only in
   the fork. Switching the pin to upstream would break the collector at import
   time, not at runtime, and buys nothing until upstream ships an equivalent.
2. **Watch the three Dependabot-invisible pins explicitly** with
   `scripts/check_upstream_pins.py`, run weekly by
   `.github/workflows/upstream-drift.yml`. The checker reads the pins from the
   files that hold them, compares each against its default branch with
   `git ls-remote`, and opens a single `security`-labelled issue when one moved.
3. **Report a fork and its parent as two rows.** A fork's own head is ours and
   is not drift; the verdict is the parent row, decided by the upstream-ahead
   commit count, so a fork that has merged every upstream commit reports 0 and
   is current.
4. **Fail loudly when the check cannot complete.** A pin that changed shape, or
   a repository (or fork parent) that cannot be read, exits 2 rather than
   passing: a green run over fewer pins than it was written to watch is the
   failure that looks like success.

## Consequences

- The collector keeps working against the fork; the drift issue tells us when
  upstream has moved and by how much, without auto-bumping anything. Pins move
  in their own commit, with a reason, per the existing dependency policy.
- The monitoring depends on `github.com` being reachable; a failure is loud
  (exit 2), never a silent "no drift".
- If `investigate()` is ever merged upstream, this decision is revisited: the
  pin moves to `OpenOSINT/OpenOSINT` and the fork is retired. Until then the
  fork is a documented, deliberately-maintained divergence, not an accident.
