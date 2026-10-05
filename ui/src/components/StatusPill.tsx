import type { Tone } from '../lib/format';

export function StatusPill({ label, tone }: { label: string; tone: Tone }) {
  return <span className={`status-pill ${tone}`.trim()}>{label}</span>;
}
