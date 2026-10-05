export const locales = ['es', 'en'] as const;
export type Locale = (typeof locales)[number];

export type TranslationStrings = {
  appTitle: string;
  controlCenter: string;
  overview: string;
  targets: string;
  runs: string;
  mainNavigation: string;
  languageSwitcher: string;
  switchToEnglish: string;
  switchToSpanish: string;
  skipToContent: string;
  operationsOverview: string;
  homeSummary: string;
  healthChecking: string;
  unavailable: string;
  apiStatus: string;
  currentVersion: string;
  operationalMode: string;
  apiUnavailable: string;
  apiUnavailableBody: string;
  loadingTargets: string;
  unableToLoadTargets: string;
  enabled: string;
  disabled: string;
  loadingRuns: string;
  unableToLoadRuns: string;
  pageNotFound: string;
  pageNotFoundBody: string;
  discoveryFirst: string;
};

export const translations: Record<Locale, TranslationStrings> = {
  es: {
    appTitle: 'OSINT Orchestrator',
    controlCenter: 'Centro de control',
    overview: 'Resumen',
    targets: 'Objetivos',
    runs: 'Ejecuciones',
    mainNavigation: 'Navegación principal',
    languageSwitcher: 'Selector de idioma',
    switchToEnglish: 'Cambiar a inglés',
    switchToSpanish: 'Cambiar a español',
    skipToContent: 'Saltar al contenido',
    operationsOverview: 'Resumen operativo',
    homeSummary: 'Supervisa objetivos activos, revisa las ejecuciones más recientes y mantén la cadena de evidencia visible para el equipo.',
    healthChecking: 'Comprobando...',
    unavailable: 'No disponible',
    apiStatus: 'Estado de la API',
    currentVersion: 'Versión actual',
    operationalMode: 'Modo operativo',
    apiUnavailable: 'API no disponible',
    apiUnavailableBody: 'La salud del backend no fue accesible desde el navegador. Verifique que la API local esté activa.',
    loadingTargets: 'Cargando objetivos...',
    unableToLoadTargets: 'No se pudieron cargar los objetivos.',
    enabled: 'Habilitado',
    disabled: 'Deshabilitado',
    loadingRuns: 'Cargando ejecuciones recientes...',
    unableToLoadRuns: 'No se pudo cargar el historial de ejecuciones.',
    pageNotFound: 'Página no encontrada',
    pageNotFoundBody: 'La ruta solicitada no existe en este panel.',
    discoveryFirst: 'Primero descubrimiento',
  },
  en: {
    appTitle: 'OSINT Orchestrator',
    controlCenter: 'Control centre',
    overview: 'Overview',
    targets: 'Targets',
    runs: 'Runs',
    mainNavigation: 'Main navigation',
    languageSwitcher: 'Language switcher',
    switchToEnglish: 'Switch to English',
    switchToSpanish: 'Switch to Spanish',
    skipToContent: 'Skip to content',
    operationsOverview: 'Operations overview',
    homeSummary: 'Monitor active targets, inspect the latest runs and keep the evidence chain visible to the team.',
    healthChecking: 'Checking...',
    unavailable: 'Unavailable',
    apiStatus: 'API status',
    currentVersion: 'Current version',
    operationalMode: 'Operational mode',
    apiUnavailable: 'API unavailable',
    apiUnavailableBody: 'Backend health was not reachable from the browser. Verify the local API is running.',
    loadingTargets: 'Loading targets...',
    unableToLoadTargets: 'Unable to load targets.',
    enabled: 'Enabled',
    disabled: 'Disabled',
    loadingRuns: 'Loading recent runs...',
    unableToLoadRuns: 'Unable to load run history.',
    pageNotFound: 'Page not found',
    pageNotFoundBody: 'The route you requested does not exist in this shell.',
    discoveryFirst: 'Discovery first',
  },
};

export const defaultLocale: Locale = 'es';
