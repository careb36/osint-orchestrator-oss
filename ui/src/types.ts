export type HealthStatus = {
  status: string;
  version?: string;
};

export type TargetSummary = {
  id: string;
  fqdn: string;
  authorization?: string;
  enabled?: boolean;
};

export type RunSummary = {
  id: string;
  targetId: string;
  status: string;
  createdAt: string;
};

export type ArtifactKind = 'report' | 'finding' | 'evidence' | 'manifest';

export type RunDetail = {
  id: string;
  targetId: string;
  status: string;
  createdAt: string;
  summary?: string;
};
