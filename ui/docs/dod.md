# UI2 phased definition of done

## Phase 1: foundation shell

The goal of this phase is to establish a stable app shell, reliable API access, and predictable UX primitives.

- [ ] Shared application shell with clear navigation and consistent layout.
- [ ] Typed API client and a bounded error-handling strategy.
- [ ] Loading, empty, and error states for every major route.
- [ ] Global error boundary with visible recovery path.
- [ ] Responsive layout that remains legible on narrow screens.
- [ ] Unit tests cover the shell and fallback states.

Definition of done for Phase 1: the shell is stable enough to ship to operators without bespoke page-level fixes, and all routes are accessible to a future feature team without reworking the base layout.

## Phase 2: operations overview

The goal of this phase is to make the running system legible to an analyst without deep investigation work.

- [ ] Dashboard with target health, current runs, and recent findings.
- [ ] Alert and issue overview with priority cues and triage affordances.
- [ ] Search and filtering across targets and recent investigations.
- [ ] Status cues that distinguish queued, in progress, completed, and failed states.
- [ ] Empty-state guidance when no runs or findings are present.
- [ ] Core KPI cards and a review path that surfaces the baseline metrics described in the KPI document.

Definition of done for Phase 2: an analyst can open the dashboard and determine what needs attention without navigating across multiple disconnected tools.

## Phase 3: investigation and evidence review

The goal of this phase is to support evidence review and decision-making within the same product flow.

- [ ] Target detail and run detail views with evidence timelines.
- [ ] Risk summary and supporting facts aligned to the backend report model.
- [ ] Evidence review controls that show provenance and confidence alongside the result.
- [ ] Search, filters, and drill-down patterns that support deeper investigation.
- [ ] Clear handoff from evidence review to report output or follow-up action.
- [ ] No uncaught runtime errors during a typical analyst investigation path.

Definition of done for Phase 3: an analyst can investigate a target from dashboard to evidence review without leaving the product or losing context.

## Phase 4: reporting and operations handoff

The goal of this phase is to close the loop between investigation and human-ready outputs.

- [ ] Report and export path aligned to the signed-report workflow.
- [ ] Historical run review with clear state and result transitions.
- [ ] Handover actions documented and discoverable for operators.
- [ ] Performance and accessibility pass on the main analyst journeys.
- [ ] KPI telemetry confirms the adoption, MTTR, and task completion targets are met or trending toward them.

Definition of done for Phase 4: the UI supports the operational lifecycle from monitoring to investigation to handoff with measurement evidence that the workflow is materially improving analyst speed and clarity.

## Phase gate rule

A phase is only considered complete when all checklists for that phase are green and the relevant KPI trend is stable enough to confirm the next phase starts from the correct baseline.
