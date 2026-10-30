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
    # History mode reads git objects, so the working copy plays no part.
    gitleaks detect --source . --redact || status=1
  else
    # Scan what could reach the repository — the tracked files plus the
    # untracked ones git does not ignore — and not the working copy as a whole.
    # `gitleaks --no-git --source .` reads ignored files too, and the README
    # tells every operator to keep live credentials in `.env`: the guard then
    # failed locally on a leak the public repository cannot see, while CI (a
    # clean checkout, no `.env`) passed. A guard that disagrees with CI for
    # following the documentation teaches people to ignore it.
    secrets_dir=$(mktemp -d)
    trap 'rm -rf "$secrets_dir"' EXIT
    while IFS= read -r -d '' tracked; do
      [ -f "$tracked" ] || continue  # deleted in the working tree, still indexed
      mkdir -p "$secrets_dir/$(dirname "$tracked")"
      cp "$tracked" "$secrets_dir/$tracked"
    done < <(git ls-files -z -c -o --exclude-standard)
    # Run from inside the copy so a finding names `.env`, not `/tmp/…/.env`.
    ( cd "$secrets_dir" && gitleaks detect --no-git --source . --redact ) || status=1
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
