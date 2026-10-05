/**
 * The operator's current locale as plain module state, so modules that are
 * not React components (the API client, telemetry) read the same value the
 * LocaleProvider resolved instead of scraping the document. Unset until the
 * provider commits; callers treat null as "not chosen yet".
 */
let current: string | null = null;

export function setCurrentLocale(locale: string | null): void {
  current = locale;
}

export function currentLocale(): string | null {
  return current;
}
