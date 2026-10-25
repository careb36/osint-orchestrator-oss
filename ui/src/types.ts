// Shapes as the orchestrator API returns them (orchestrator/api.py,
// orchestrator/models.py). Field names are the backend's: snake_case.

export type HealthCheck = {
  status: 'ok' | 'degraded' | 'offline' | string;
  detail: string;
  hint?: string;
  action?: string;
  recovery?: string;
};

export type HealthStatus = {
  status: 'ok' | 'degraded' | 'offline' | string;
  version?: string;
  updated_at?: string;
  checks?: Record<string, HealthCheck>;
};

export type TargetSummary = {
  id: string;
  fqdn: string;
  enabled: boolean;
  authorization: string;
  purpose: string;
  llm?: string;
  /** Target.classification: "osint" (open sources, cloud allowed) or "restricted" (local model only). */
  classification?: string;
  /** Where the model prompts actually go: "none", "ollama" or a cloud provider (API-computed). */
  processing?: string;
  language?: string | null;
  collectors?: Record<string, { enabled?: boolean } & Record<string, unknown>>;
  schedule?: { cron?: string } & Record<string, unknown>;
};

export type RunStatus = 'pending' | 'running' | 'success' | 'partial' | 'failed' | string;

export type RunSummary = {
  id: number;
  target_id: string;
  started_at: string;
  finished_at: string | null;
  status: RunStatus;
  collectors_run: string;
  new_observables: number;
  error: string | null;
  report_path: string | null;
  manifest_sha256: string | null;
  /** Risk level of the run's finding; null without one (failed early, synthesis off, still running). */
  risk_level?: string | null;
};

export type AlertRecordSummary = {
  id?: number;
  channel?: string;
  status?: string;
  sent_at?: string | null;
  error?: string | null;
} & Record<string, unknown>;

export type RunDetail = RunSummary & {
  alerts: AlertRecordSummary[];
};

export type Finding = {
  run_id: number;
  target_id: string;
  summary: string;
  risk_level: 'unknown' | 'low' | 'medium' | 'high' | 'critical' | string;
  risk_justification: string;
  new_since_last_run: string[];
  suggested_pivots: string[];
  provider: string;
  model: string;
  duration_ms: number;
  generated_at?: string;
};

export type EvidenceRow = {
  id?: number;
  run_id: number;
  target_id: string;
  url: string;
  title: string;
  category: string;
  relevance: 'high' | 'medium' | 'low' | string;
  confidence: number;
  rationale: string;
  provider: string;
  model: string;
  created_at?: string;
};

export type DeltaRow = {
  stix_id: string;
  stix_type: string;
  value: string;
};

export type RiskTrend = {
  target_id: string;
  runs_considered: number;
  latest_run_id: number;
  latest_status: RunStatus;
  latest_risk_level: string;
  peak_risk_level: string;
  risk_history: string[];
  new_observables_history: number[];
};

export type TriggerRunResponse = {
  run_id: number;
  status: string;
  target_id: string;
};

export type ArtifactKind = 'report' | 'finding' | 'evidence' | 'manifest' | 'delta';

/** GET /targets/{id}/chain/verify (orchestrator/evidence.py::verify_target_chain). */
export type ChainVerification = {
  ok: boolean;
  checked: number;
  unsealed: number;
  first_broken_run_id: number | null;
  reason: string | null;
  detail: string | null;
  anchor_run_id: number | null;
  anchor_previous_manifest_sha256: string | null;
  /** Operator-language explanation of `reason`, set by the API when the chain is broken. */
  message?: string;
};

export type AlertCaseState = 'open' | 'acknowledged' | 'resolved' | string;
export type AlertCaseReason = 'new_observables' | 'risk_level' | 'run_failure' | string;

/** One triage item per run that met an alert rule (orchestrator/models.py::AlertCase). */
export type AlertCase = {
  id: number;
  run_id: number;
  target_id: string;
  created_at: string;
  run_status: RunStatus;
  risk_level: string;
  new_observable_count: number;
  reason: AlertCaseReason;
  state: AlertCaseState;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  note: string | null;
};

export type AlertCaseList = {
  items: AlertCase[];
  total: number;
  limit: number;
  offset: number;
};

/** Body of POST /alerts/{id}/ack and /resolve: free text, there are no users (ADR-005). */
export type AlertCaseAction = { by: string; note?: string };
