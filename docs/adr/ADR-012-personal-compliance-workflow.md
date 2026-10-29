# ADR-012: Personal identities and professional dossiers

**Status:** Accepted for this implementation

## Context

The intended end users are Compliance accountants. One system administrator
owns technical operation. ADR-005 and ADR-010's shared-key operator console
cannot attribute professional decisions or distinguish those responsibilities.
An automated run is supporting evidence, not the professional decision itself.

## Decision

Amend ADR-005, ADR-006 and ADR-010 with native personal accounts and server-side
sessions, keeping the optional OIDC proxy as a separate perimeter and API keys
for trusted automation. Existing keys retain their legacy control privileges;
previously shared operator keys must be rotated before granting staff access.
Machine keys cannot approve dossiers or impersonate staff.

Passwords use salted PBKDF2-HMAC-SHA256 with 600,000 iterations. Session tokens
are random, stored as SHA-256 digests, expire after eight hours, and are revoked
on password reset/change or account disable. Cookies are HttpOnly, SameSite
Strict and Secure by default. Unsafe browser requests require a custom header
and a matching Origin when one is supplied. Five failed attempts lock an
account for fifteen minutes. Production still requires HTTPS and edge rate
limiting. No password recovery service or default accounts are shipped.

The first administrator is created locally by CLI. Once any account exists,
an empty automation key never reopens anonymous access. Accountants cannot
reload the scheduler, replay technical queues, import external bundles, or
manage accounts. Administrators manage technical access but use an accountant
identity for professional evidence decisions and finalization. Administration
does not automatically approve a Compliance conclusion.

Dossiers capture entity identity and scope separately from collector settings.
They associate existing runs, record reasoned confirmation or dismissal of
each evidence item, and append authenticated events. Mutations compare the
expected revision to prevent silent lost updates. Finalization checks complete
source stages and integrity and freezes a snapshot, a PDF, its digest and an
internal HMAC. Automated and professional risk remain separate values.
Reopening records a reason and creates a subsequent report version; previous
reports are not rewritten. This is an application audit and internal integrity
control, not an externally certified signature or trusted timestamp.

The deployment represents one practice: authenticated staff share its dossiers
and operational source data. This does not introduce tenant/client isolation,
case-level assignment permissions, or a mandatory second professional reviewer.
Those require an explicit authorization model before hosting multiple practices.
Runs associated with dossiers are excluded from automatic operational retention.
Released case-report PDFs are stored with their snapshots in SQLite and must
be included in database backups. There is no dossier deletion endpoint.

## Run readiness and report rendering

Persist collection, qualification, synthesis, report and integrity outcomes
independently. Qualification failures survive subsequent stages. Incomplete
qualification or synthesis failure degrades the overall run; missing reports
fail it and missing PDFs or seals cannot claim success. Skipped steps remain
visible and never imply an assessment took place. Historical runs retain
`not_recorded` for newly introduced fields and cannot silently satisfy current
finalization checks. Existing signed files are never rewritten by migration.

PDFs bundle the licensed DejaVu Sans fonts, wrap within page margins, support
the font's Unicode character repertoire, and show the summary before technical
appendices. Test text and page bounds as well as file existence.
