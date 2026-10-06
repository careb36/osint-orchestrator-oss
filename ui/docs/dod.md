# UI2 phased definition of done

## Phase 1: foundation shell

The goal of this phase is to establish a stable app shell, reliable API access, and predictable UX primitives.

- [x] Shared application shell with clear navigation and consistent layout. *`src/App.tsx`, routes from `src/routes.ts`.*
- [x] Typed API client and a bounded error-handling strategy. *`src/lib/api.ts` (`ApiError`, `optional` 404s, bounded telemetry ring).*
- [x] Loading, empty, and error states for every major route. *`src/components/PageState.tsx`, used by every view.*
- [x] Global error boundary with visible recovery path. *`src/components/ErrorBoundary.tsx`: the fallback offers Try again and Back to the overview, and the boundary resets on route change so one crashed view never takes the shell down.*
- [x] Responsive layout that remains legible on narrow screens. *Top bar and navigation stack under 720 px; tables scroll within the content column.*
- [x] Unit tests cover the shell and fallback states. *`src/App.test.tsx`, `src/components/ErrorBoundary.test.tsx`, `src/a11y.test.tsx`.*

Definition of done for Phase 1: the shell is stable enough to ship to operators without bespoke page-level fixes, and all routes are accessible to a future feature team without reworking the base layout.

## Phase 2: operations overview

The goal of this phase is to make the running system legible to an analyst without deep investigation work.

- [x] Dashboard with target health, current runs, and recent findings.
- [ ] Alert and issue overview with priority cues and triage affordances. *Deferred: the API exposes alert deliveries per run only (`GET /runs/{id}`), not an alert list or acknowledgement state, so there is nothing to triage from the UI yet.*
- [x] Search and filtering across targets and recent investigations.
- [x] Status cues that distinguish queued, in progress, completed, and failed states.
- [x] Empty-state guidance when no runs or findings are present.
- [x] Core KPI cards and a review path that surfaces the baseline metrics described in the KPI document. *Task completion time is shown as the median run time; adoption and MTTR need telemetry the backend does not emit and are left out per the KPI guardrail.*

Definition of done for Phase 2: an analyst can open the dashboard and determine what needs attention without navigating across multiple disconnected tools.

## Phase 3: investigation and evidence review

The goal of this phase is to support evidence review and decision-making within the same product flow.

- [x] Target detail and run detail views with evidence timelines. *Run detail: finding, evidence, delta, report and manifest tabs; target detail: risk history and runs.*
- [x] Risk summary and supporting facts aligned to the backend report model.
- [x] Evidence review controls that show provenance and confidence alongside the result.
- [x] Search, filters, and drill-down patterns that support deeper investigation.
- [x] Clear handoff from evidence review to report output or follow-up action. *Evidence tab leads to the report and to the handoff block; the block verifies the chain, exports the signed bundle and the PDF, copies a handoff summary and starts a follow-up run.*
- [x] No uncaught runtime errors during a typical analyst investigation path. *`src/App.e2e.test.tsx` walks overview → targets → target → runs → run (finding, evidence with a filter, report, manifest) → back with a `console.error` spy and the telemetry ring both required to stay empty.*

Definition of done for Phase 3: an analyst can investigate a target from dashboard to evidence review without leaving the product or losing context.

## Phase 4: reporting and operations handoff

The goal of this phase is to close the loop between investigation and human-ready outputs.

- [x] Report and export path aligned to the signed-report workflow. *`GET /runs/{id}/bundle` ships the run directory with its `manifest.json`, so the recipient re-hashes every file and checks the signature offline; `GET /runs/{id}/report.pdf` is the human-ready copy.*
- [x] Historical run review with clear state and result transitions. *Every run row carries its risk level and a Change column (status and risk against the target's previous run); target detail opens with a timeline of its runs, oldest first.*
- [x] Handover actions documented and discoverable for operators. *One block at the end of every run detail; runbook in `docs/operations.md` (Handover actions).*
- [x] Performance and accessibility pass on the main analyst journeys. *Accessibility: axe-core smoke tests over every main view (`ui/src/a11y.test.tsx`). Performance: views are code-split and loaded on demand, the libraries live in two vendor chunks that keep their immutable cache entry across dashboard releases; the single 284.8 kB script became a 37.8 kB shell plus 157.6 kB (React, router) and 53.2 kB (query) vendor chunks and 0.3 to 9.3 kB per view, so a release that changes one view invalidates that view's chunk only. List refreshes are bounded (10 s while a run is active, otherwise none), and the overview makes one bounded finding request per recent run.*
- [ ] KPI telemetry confirms the adoption, MTTR, and task completion targets are met or trending toward them. *Needs production usage, not code: task completion time (median run duration) is on the overview and can be read weekly; adoption and MTTR are withheld from the scorecard under the KPI guardrail until the backend emits operator sessions and alert acknowledgements (see `kpis.md`, Scorecard today).*

Definition of done for Phase 4: the UI supports the operational lifecycle from monitoring to investigation to handoff with measurement evidence that the workflow is materially improving analyst speed and clarity.

## Phase gate rule

A phase is only considered complete when all checklists for that phase are green and the relevant KPI trend is stable enough to confirm the next phase starts from the correct baseline.
