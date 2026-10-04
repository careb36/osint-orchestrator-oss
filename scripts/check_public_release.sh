#!/usr/bin/env bash
# Public-release guard.
#
# Fails when the tracked tree still carries references that must never reach
# the public repository (names of specific public bodies, official government
# portals) or when gitleaks finds something that looks like a credential.
# Run it before opening a PR; CI runs it too.
#
#   bash scripts/check_public_release.sh            # tree only (fast)
#   CHECK_HISTORY=1 bash scripts/check_public_release.sh   # also scan git history
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Case-insensitive. Kept in one place on purpose: extend here, not in CI.
PATTERN='senaclaft|uiaf|\bbcu\b|banco central|secretar[ií]a nacional|gub\.uy'
status=0

echo "== Tracked file contents"
if git grep -nIiE "$PATTERN" -- . ':!scripts/check_public_release.sh'; then
  echo "FAIL: forbidden references found in tracked files"
  status=1
else
  echo "OK: no forbidden references in file contents"
fi

echo "== Tracked file names"
if git ls-files | grep -iE 'senaclaft|uiaf|\bbcu\b'; then
  echo "FAIL: forbidden references in file names"
  status=1
else
  echo "OK: file names are clean"
fi

echo "== Secrets (gitleaks)"
if command -v gitleaks >/dev/null 2>&1; then
  if [ "${CHECK_HISTORY:-0}" = "1" ]; then
    gitleaks detect --source . --redact || status=1
  else
    gitleaks detect --no-git --source . --redact || status=1
  fi
else
  echo "SKIP: gitleaks is not installed (https://github.com/gitleaks/gitleaks)"
fi

if [ "$status" -ne 0 ]; then
  echo "Public-release guard FAILED"
else
  echo "Public-release guard passed"
fi
exit "$status"
