export type UiTelemetryEntry = {
  timestamp: string;
  event: string;
  detail: Record<string, unknown>;
  language: string;
  path: string;
};

const UI_TELEMETRY_MAX_ENTRIES = 25;
const UI_TELEMETRY_MAX_DETAIL_CHARS = 500;

export const uiTelemetry: UiTelemetryEntry[] = [];

function truncateTelemetryText(value: unknown): string {
  const text = String(value ?? '');
  return text.length > UI_TELEMETRY_MAX_DETAIL_CHARS
    ? `${text.slice(0, UI_TELEMETRY_MAX_DETAIL_CHARS)}…`
    : text;
}

export function trackUiTelemetry(event: string, detail: Record<string, unknown> = {}): void {
  const sanitizedDetail = { ...detail };

  if (typeof sanitizedDetail.path === 'string') {
    sanitizedDetail.path = sanitizedDetail.path.split('?')[0];
  }

  for (const key of ['message', 'stack', 'filename', 'componentStack']) {
    if (typeof sanitizedDetail[key] === 'string') {
      sanitizedDetail[key] = truncateTelemetryText(sanitizedDetail[key]);
    }
  }

  const payload: UiTelemetryEntry = {
    timestamp: new Date().toISOString(),
    event,
    detail: sanitizedDetail,
    language: typeof document !== 'undefined' && document.documentElement.lang ? document.documentElement.lang : 'en',
    path: window.location.pathname,
  };

  uiTelemetry.push(payload);
  if (uiTelemetry.length > UI_TELEMETRY_MAX_ENTRIES) {
    uiTelemetry.shift();
  }

  console.info('ui-telemetry', payload);
}

export function reportUiError(error: unknown, context: Record<string, unknown> = {}): void {
  const message = error instanceof Error ? error.message : String(error ?? 'Unknown UI error');
  const stack = error instanceof Error ? error.stack : '';

  trackUiTelemetry('ui_error', {
    ...context,
    message,
    stack: stack || undefined,
  });
}
