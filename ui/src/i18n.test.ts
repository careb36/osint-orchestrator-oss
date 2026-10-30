import { defaultLocale, detectLocale, format, LOCALE_STORAGE_KEY, locales, translate, translateValue, translations, type MessageKey } from './i18n';

describe('UI catalogue', () => {
  it('carries every key in every locale, with no empty text (ADR-004)', () => {
    const keys = Object.keys(translations.en) as MessageKey[];
    expect(keys.length).toBeGreaterThan(100);
    for (const locale of locales) {
      expect(Object.keys(translations[locale]).sort()).toEqual([...keys].sort());
      for (const key of keys) {
        expect(translations[locale][key].trim(), `${locale}.${key}`).not.toBe('');
      }
    }
  });

  it('keeps the same placeholders in both languages', () => {
    const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    for (const key of Object.keys(translations.en) as MessageKey[]) {
      expect(placeholders(translations.es[key]), key).toEqual(placeholders(translations.en[key]));
    }
  });

  it('defaults to Spanish and interpolates variables', () => {
    expect(defaultLocale).toBe('es');
    expect(translate('es', 'run.accepted', { runId: 7, targetId: 'acme' })).toBe('Ejecución #7 aceptada para acme.');
    expect(translate('en', 'run.accepted', { runId: 7, targetId: 'acme' })).toBe('Run #7 accepted for acme.');
    expect(format('{a} and {missing}', { a: 1 })).toBe('1 and {missing}');
  });

  it('labels persisted identifiers without changing unknown ones', () => {
    expect(translateValue('es', 'running')).toBe('en curso');
    expect(translateValue('en', 'running')).toBe('running');
    expect(translateValue('es', 'weird-status')).toBe('weird-status');
  });

  describe('detectLocale', () => {
    afterEach(() => {
      vi.unstubAllGlobals();
      window.localStorage.clear();
    });

    it('prefers the stored choice, then a supported browser language, then Spanish', () => {
      vi.stubGlobal('navigator', { ...navigator, language: 'fr-FR' });
      expect(detectLocale()).toBe('es');

      vi.stubGlobal('navigator', { ...navigator, language: 'en-GB' });
      expect(detectLocale()).toBe('en');

      window.localStorage.setItem(LOCALE_STORAGE_KEY, 'es');
      expect(detectLocale()).toBe('es');

      window.localStorage.setItem(LOCALE_STORAGE_KEY, 'klingon');
      expect(detectLocale()).toBe('en');
    });
  });
});
