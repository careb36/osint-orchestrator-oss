import { afterEach, describe, expect, it, vi } from 'vitest';
import { setCurrentLocale } from './locale';
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

  describe('language field', () => {
    afterEach(() => {
      setCurrentLocale(null);
      document.documentElement.lang = '';
    });

    it('uses the resolved locale, then the document language, then a last-resort marker', () => {
      const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => undefined);

      // Before the provider commits (an error boundary on the first render):
      // the document language index.html declares.
      document.documentElement.lang = 'es';
      reportUiError(new Error('early crash'));
      expect(uiTelemetry[uiTelemetry.length - 1]?.language).toBe('es');

      setCurrentLocale('en');
      trackUiTelemetry('after_commit');
      expect(uiTelemetry[uiTelemetry.length - 1]?.language).toBe('en');

      setCurrentLocale(null);
      document.documentElement.lang = '';
      trackUiTelemetry('nothing_known');
      expect(uiTelemetry[uiTelemetry.length - 1]?.language).toBe('unset');

      infoSpy.mockRestore();
    });
  });
});
