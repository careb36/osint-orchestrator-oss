# Compliance review workflow

The personal workflow is for one practice with shared dossiers. It does not
isolate multiple organizations or clients into separate security boundaries.
Use separate deployments where that isolation is required.

## Administrator setup

Upgrade the application and back up SQLite, reports and signing keys first.
Startup applies additive migrations 0011 and 0012. Existing signed reports are
left untouched. Their new stage fields say `not_recorded`; associate a new,
complete review before issuing a report through the professional workflow.

Create the first administrator from the repository root using the installed
Python environment and the same configuration/database as the running API:

```sh
python -m orchestrator.accounts administrator --name 'System administrator'
```

The CLI prompts twice for a password of at least twelve characters; it never
accepts a password in command-line arguments or prints one. No default account
or password is installed. In Compose use the equivalent command through
`docker compose exec orchestrator`. Once an account exists, the dashboard
offers personal sign-in. Anonymous access remains disabled even if all accounts
are inactive or the machine key is empty.

Serve production over HTTPS and retain `ORCHESTRATOR_COOKIE_SECURE=true`.
Configure a trusted TLS reverse proxy and trusted forwarded headers so the API
sees the public scheme/host correctly for Origin checks. Apply edge login rate
limits in addition to the per-account lockout. Use `false` only for local HTTP
development; do not disable cookie protections in a public deployment.

After signing in, open **My account** to create accountant accounts, disable
their access, reset their passwords or change your own password. Resets and
disables revoke existing sessions; an own-password change ends every session.
Deliver temporary passwords through a secure channel and have each person
change theirs. Staff contact the administrator for recovery. Administrator
accounts cannot be disabled through the web API; recover a lost administrator
by provisioning another locally and reviewing the identity store offline.

Existing `ORCHESTRATOR_API_KEY` values remain privileged automation credentials.
Rotate any keys previously distributed to human operators before onboarding
staff. Personal sign-in clears old browser key storage. The OIDC proxy remains
an optional additional perimeter and does not provision native accounts.

## Accountant workflow

1. Open **Dossiers**, create a dossier with legal/full name, person/company,
   country, identifier when available, and authorized purpose/scope. A website
   is not required to create the dossier. Edit identity fields before finalizing;
   changes are recorded in the history.
2. Associate one or more existing source reviews by run number. Source reviews
   still use the administrator's configured targets and sources; the dossier
   form does not configure new collectors or contact third parties by itself.
3. Inspect each source's collection, qualification, synthesis, report and
   integrity outcomes. `Not executed` and `Not recorded` are not successful
   assessments. Partial search queries and incomplete qualification must be
   addressed before finalization.
4. Confirm or dismiss every evidence match with a reason, checking the identity
   and possible homonyms. The authenticated account is recorded automatically.
   Previous reasons remain in the event history when a decision is corrected.
5. Record the professional risk and conclusion. They are separate from the
   automated risk. Acknowledge the source/date limitations and finalize.
   Incomplete, unreviewed, unverifiable or default-key-signed sources block
   issuance. No unverified fallback bypasses these checks.
6. Download the issued PDF. The snapshot records the source evidence, automated
   finding, professional decision, author, date and source manifest digests.
   Reopen with a reason to revise the conclusion and issue a new version.
   Previously issued snapshots and PDFs remain available unchanged.

The technical administrator can manage the system and view the practice's
records; final professional decisions require an accountant account. Technical
administration is not a substitute for professional review.

## Operations and integrity

The backend verifies retained source chains before finalization. The final
snapshot's HMAC covers the PDF digest; downloads are rejected if that integrity
check fails. Preserve current and previous signing keys when rotating them.
This does not certify source truth or provide public-key nonrepudiation.

Operational retention skips runs linked to dossiers. Issued snapshots/PDFs
and event histories live in SQLite. Back up that database together with source
artifacts, configuration and signing keys; test restoration and chain/report
verification. Dossier archival/deletion and legal retention exceptions need a
separate policy before real-case production use.

Personal API routes are `/auth/status`, `/auth/login`, `/auth/me`, `/auth/logout`
and `/auth/password`. Account administration uses `/accounts`. Dossiers use
`/cases`, `/cases/{id}`, `/sources`, `/reviews`, `/finalize`, `/reopen` and
`/reports/{version}` with `/pdf` for downloads. These suffixes are relative to
`/cases/{id}`. Mutations require the current `revision` (except creation).
The OpenAPI documentation describes request schemas. Responses are not cached.

## Validation

The regression suite exercises Unicode PDFs and extracted word positions,
lost qualification warnings, permissions, CSRF, session revocation, account
lockout, missing-evidence and incomplete-source gates, stale revisions, report
version preservation and the accountant UI flow. It uses fictitious inputs
and offline mocks, not live investigations. The Poppler-dependent extraction
test reports a skip when that tool is unavailable; it is required for the
PDF layout validation performed during development of this change.
