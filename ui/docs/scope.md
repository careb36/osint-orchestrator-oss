# UI2 scope and boundaries

## Objective

The product goal is to create a single operational surface for the OSINT orchestrator that helps analysts monitor targets, understand active investigations, review supporting evidence, and act on alerts without needing a separate bespoke tool for each step.

This is a product-scoped UI effort: the UI is a front door to existing orchestration and report capabilities, not a replacement for the backend workflow or a new data-collection system.

## In scope

### Product scope

- A shared shell for the application with predictable navigation, loading states, and error handling.
- A dashboard for operational health: target statuses, active runs, recent findings, and recent alerts.
- Investigation detail screens for individual targets and runs, including a clear evidence trail.
- Review flows for qualified evidence, risk summaries, and run history.
- Search, filtering, and sorting patterns to support analyst triage.
- Reporting handoff and export affordances that are aligned to the existing signed-report workflow.

### Implementation constraints

- The UI must integrate with the existing API boundary and typed client patterns already used by the frontend shell.
- The experience should assume the backend remains the source of truth for run state and evidence.
- The design must support the same product workflows across desktop and narrow-browser widths without adding custom one-off screens.

## Out of scope

The following are explicitly not part of the UI2 super-app scope unless a separate milestone or product review approves them:

- Building a new collector or pipeline in the frontend.
- Replacing the backend risk model, STIX handling, or report-generation logic.
- Full case-management workflows such as approvals, assignment, or task queues beyond operational triage.
- Autonomy features that bypass the signed evidence chain or change the backend policy model.
- External identity, RBAC, or organisation administration features unless the core product already owns those flows.
- Mobile-native UX, offline-first editing, or broad customisation tooling for arbitrary report templates.

## Decision rule

If a feature would require new backend data contracts, new collector logic, or a change to the report-signing model, it is out of scope for UI2 and must be split into a separate product decision or follow-on milestone.

## Scope approval

This document is the approval baseline for UI2. Any future change to the super-app surface must either:

1. remain within the listed in-scope capabilities, or
2. expand the scope through a documented product change and a corresponding update to the KPI and DoD plans.
