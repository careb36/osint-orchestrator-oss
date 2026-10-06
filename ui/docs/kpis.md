# UI2 KPI baseline and targets

## KPI model

The KPI set is intentionally limited to metrics that can be measured with the telemetry already produced by the frontend shell and the orchestration backend. The UI should not create a parallel reporting layer; it should surface the metrics that are already available from the runtime.

## Data sources available today

The following sources are sufficient to measure the baseline and target state without introducing new instrumentation:

- Frontend route and page-view events from the Vite React shell.
- API client request success/error and latency from the shared typed API boundary.
- Backend run lifecycle timestamps for new, queued, in-progress, completed, and failed states.
- Alert and evidence timestamps already emitted by the orchestrator when a condition changes state.

## KPI definitions

| KPI | Formula | Baseline definition | Target |
| --- | --- | --- | --- |
| Adoption | `weekly_active_operators / licensed_operators` | Baseline is the first four-week measurement after the UI2 shell is live. | `>= 60%` weekly active usage of licensed operators by the end of Phase 3. |
| MTTR | `median(minutes between first alert timestamp and acknowledgement/resolution)` | Baseline is the median for alerts generated in the prior 30 days before the new dashboard is used operationally. | `<= 30 minutes` for high-priority alerts. |
| Task completion time | `median(minutes between run created_at and final status timestamp)` | Baseline is the median end-to-end duration for standard one-target investigations in the current backend workflow. | `<= 12 minutes` for standard investigations in the default operating profile. |

## Measurement method

- Adoption is measured from the app session and authenticated operator activity captured in the browser and backend logs.
- MTTR is derived from alert state transitions recorded by the orchestrator as alerts move from `new` to `acknowledged` or `resolved`.
- Task completion time is computed from the timestamp between a run being created and the final run status being recorded as `completed` or `failed`.

## Operational interpretation

- Adoption is the leading indicator of platform value: if the dashboard is not used repeatedly, the workflow is still fragmented.
- MTTR indicates whether the UI improves analyst actionability and reduces time to triage.
- Task completion time shows whether the UI surfaces status clearly enough to reduce context switching and waiting.

## Reporting cadence

The dashboard should surface these KPIs in weekly review windows, with the baseline established during the first live rollout period and targets evaluated after each phase gate.

## Scorecard today

What the dashboard can measure with the events that exist, checked against the
guardrail below:

| KPI | Status | Where |
| --- | --- | --- |
| Task completion time | Measured: median minutes from `started_at` to `finished_at` over the terminal runs of the loaded window (100 most recent) | Overview, key figures |
| Adoption | Withheld: no operator identity or session event exists (ADR-005: one shared API key, no users) | — |
| MTTR | Withheld: alerts have a dispatch status but no acknowledgement or resolution event | — |

Adoption and MTTR return to the scorecard when the backend emits the events
they need; until then the two targets above are not evaluated.

## Guardrail

If a KPI cannot be computed from the current telemetry set, it is not a valid UI2 KPI and should be removed from the scorecard until the underlying event is available.
