import { describe, expect, it, vi } from 'vitest';
import { reportUiError, trackUiTelemetry, uiTelemetry } from './telemetry';

describe('frontend telemetry', () => {
  it('records structured browser telemetry with sanitised detail', () => {
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => undefined);
    const longMessage = 'x'.repeat(600);

    trackUiTelemetry('health_check', {
      message: longMessage,
      path: '/health?token=abc',
    });

    const entry = uiTelemetry[uiTelemetry.length - 1];
    expect(entry?.event).toBe('health_check');
    expect(entry?.detail.path).toBe('/health');
    expect(String(entry?.detail.message)).toContain('…');
    expect(String(entry?.detail.message)).toHaveLength(501);
    expect(infoSpy).toHaveBeenCalledWith('ui-telemetry', expect.objectContaining({ event: 'health_check' }));

    infoSpy.mockRestore();
  });

  it('records a formatted error event for handler failures', () => {
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => undefined);

    reportUiError(new Error('boom'), { source: 'workspace' });

    const entry = uiTelemetry[uiTelemetry.length - 1];
    expect(entry?.event).toBe('ui_error');
    expect(String(entry?.detail.message)).toBe('boom');
    expect(entry?.detail.source).toBe('workspace');
    expect(infoSpy).toHaveBeenCalledWith('ui-telemetry', expect.objectContaining({ event: 'ui_error' }));

    infoSpy.mockRestore();
  });
});
