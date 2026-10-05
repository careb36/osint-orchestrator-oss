/* eslint-disable react-refresh/only-export-components */
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

/**
 * Operator-facing text of the dashboard, Spanish first (ADR-004: operators
 * read Spanish, code and identifiers stay English). Every key carries both
 * languages; `i18n.test.ts` fails otherwise, like the backend catalogue test.
 *
 * Persisted identifiers (run statuses, risk levels, relevances) keep their
 * English value in the data; `translateValue` gives them a display label.
 */
export const locales = ['es', 'en'] as const;
export type Locale = (typeof locales)[number];
export const defaultLocale: Locale = 'es';
export const LOCALE_STORAGE_KEY = 'osint-operator-locale';

const en = {
  // shell
  appTitle: 'OSINT Orchestrator',
  appSubtitle: 'Operator dashboard',
  skipToContent: 'Skip to content',
  mainNavigation: 'Main navigation',
  languageSwitcher: 'Language',
  'locale.es': 'Español',
  'locale.en': 'English',
  'nav.overview': 'Overview',
  'nav.targets': 'Targets',
  'nav.runs': 'Runs',
  forgetKey: 'Forget key',
  checkingAccess: 'Checking API access…',
  'unavailable.title': 'API unavailable',
  'unavailable.body': 'The orchestrator API could not be reached.',
  'unavailable.bodyWithStatus': 'The orchestrator API could not be reached (status {status}).',
  'unavailable.bodyNetwork': 'The orchestrator API could not be reached: the request did not get an answer (network error or server down).',
  retry: 'Retry',
  'error.title': 'Something went wrong.',
  'error.body': 'The UI hit an unexpected error. Refresh to try again.',
  'state.unableToLoad': 'Unable to load this view',
  eyebrow: 'Operations',
  // key gate
  'gate.eyebrow': 'Operator access',
  'gate.title': 'API key required',
  'gate.lede.before': 'This dashboard reads the orchestrator API with the operator key (',
  'gate.lede.after': '). The key stays in this browser tab; tick “remember” to keep it on this device.',
  'gate.formTitle': 'Enter the API key',
  'gate.keyLabel': 'API key',
  'gate.remember': 'Remember on this browser',
  'gate.help': 'Without “remember” the key is forgotten when the tab closes.',
  'gate.submit': 'Use key',
  'gate.checking': 'Checking…',
  'gate.empty': 'Enter the API key.',
  'gate.rejected': 'The API rejected this key.',
  'gate.unvalidated': 'Could not validate the key. {reason}',
  'gate.unknownError': 'Unable to use this key.',
  // not found
  'notFound.title': 'Page not found',
  'notFound.subtitle': 'The route you requested does not exist in this dashboard.',
  'notFound.emptyTitle': 'No matching route',
  'notFound.emptyBody': 'Use the navigation above to return to a supported view.',
  // start run
  'run.accepted': 'Run #{runId} accepted for {targetId}.',
  'run.failed': 'The run could not be started.',
  'run.failed.disabled': 'The run could not be started: the target is disabled.',
  'run.failed.inProgress': 'The run could not be started: a run is already in progress for this target.',
  'run.failed.notFound': 'The run could not be started: the target does not exist.',
  'run.failed.unauthorized': 'The run could not be started: the API key was rejected.',
  'run.failed.status': 'The run could not be started (status {status}).',
  'run.serverDetail': 'Server detail: {detail}',
  'run.start': 'Start run',
  'run.running': 'Running…',
  'run.startFor': ' for {targetId}',
  // common
  never: 'never',
  noRuns: 'no runs',
  yes: 'Yes',
  no: 'No',
  disabledSuffix: ' · disabled',
  'count.of': '{visible} of {total}',
  clearFilters: 'Clear filters',
  search: 'Search',
  soFar: 'so far',
  back: 'Back',
  // columns
  'col.target': 'Target',
  'col.run': 'Run',
  'col.collectors': 'Collectors',
  'col.lastRun': 'Last run',
  'col.status': 'Status',
  'col.risk': 'Risk',
  'col.peakRisk': 'Peak risk',
  'col.newObservables': 'New observables',
  'col.started': 'Started',
  'col.elapsed': 'Elapsed',
  'col.duration': 'Duration',
  'col.actions': 'Actions',
  'col.category': 'Category',
  'col.relevance': 'Relevance',
  'col.confidence': 'Confidence',
  'col.source': 'Source',
  'col.rationale': 'Rationale',
  'col.type': 'Type',
  'col.value': 'Value',
  // overview
  'overview.title': 'Overview',
  'overview.loadingSubtitle': 'Checking the current operating state.',
  'overview.loading': 'Loading service health, targets and runs…',
  'overview.downSubtitle': 'The orchestrator API could not be reached.',
  'overview.down': 'Neither the health check nor the target inventory answered. Verify the API is running and reachable from this browser.',
  'overview.subtitle': 'What needs attention: active runs, risk, failures and coverage at a glance.',
  'overview.kpis': 'Key figures',
  'overview.window': 'Run-based figures come from the {count} most recent runs the API returns (at most 100).',
  'kpi.activeRuns': 'Active runs',
  'kpi.activeRuns.caption': 'pending or running now',
  'kpi.runs24h': 'Runs in 24 h',
  'kpi.runs24h.caption': 'started in the last day, within the runs loaded',
  'kpi.successRate': 'Success rate',
  'kpi.successRate.caption': 'of {count} finished runs loaded',
  'kpi.medianRun': 'Median run time',
  'kpi.medianRun.caption': 'task completion time, start to final status',
  'kpi.atRisk': 'Targets at risk',
  'kpi.atRisk.caption': 'latest finding high or critical',
  'kpi.coverage': 'Coverage, 7 days',
  'kpi.coverage.caption': 'enabled targets with a run this week, within the runs loaded',
  'overview.targets': 'Targets by attention',
  'overview.trendsDown': 'Risk levels are unavailable right now; the table shows run status only.',
  'overview.noTargets.title': 'No targets configured',
  'overview.noTargets.body': 'Add a target to targets.yaml and reload the scheduler; it appears here with its runs and risk.',
  'overview.inventoryDown': 'The target inventory is unavailable.',
  'overview.active': 'Active runs',
  'overview.runsDown': 'Run history is unavailable.',
  'overview.nothingRunning.title': 'Nothing running',
  'overview.nothingRunning.body': 'No run is pending or in progress. Start one from the table above; this list refreshes itself while it runs.',
  'overview.findings': 'Recent findings',
  'overview.findingsLoading': 'Loading findings…',
  'overview.findingsFailed': '{count} finding(s) could not be loaded.',
  'overview.noRuns.title': 'No runs yet',
  'overview.noRuns.body': 'Findings appear here once a run finishes with a model synthesis.',
  'overview.goToTargets': 'Go to targets',
  'overview.noFindings.title': 'No findings for the latest runs',
  'overview.noFindings.body': 'The recent runs finished without a synthesis (no model configured, or the run failed before it). Open a run to see its evidence and delta.',
  'overview.findingLink': 'Run #{runId} · {targetId}',
  'overview.newSince': '{count} new since last run',
  'overview.health': 'Service health',
  'overview.healthDown': 'The health endpoint did not answer.',
  // targets
  'targets.title': 'Targets',
  'targets.loadingSubtitle': 'Review the active target set and coverage status.',
  'targets.loading': 'Loading targets…',
  'targets.downSubtitle': 'The target inventory is currently unavailable.',
  'targets.down': 'Unable to load targets.',
  'targets.subtitle': 'The target inventory for this operator workspace.',
  'targets.empty.title': 'No targets configured',
  'targets.empty.body': 'Add a target to targets.yaml and reload the scheduler to start tracking it.',
  'targets.filters': 'Filter targets',
  'targets.searchPlaceholder': 'id, domain, purpose or collector',
  'targets.enabled': 'Enabled',
  'targets.enabled.all': 'All',
  'targets.enabled.enabled': 'Enabled only',
  'targets.enabled.disabled': 'Disabled only',
  'targets.anyStatus': 'Any status',
  'targets.neverCollected': 'never collected',
  'targets.anyRisk': 'Any risk',
  'targets.noMatch.title': 'No targets match',
  'targets.noMatch.body': 'Clear a filter or widen the search to see more targets.',
  // runs
  'runs.title': 'Runs',
  'runs.loadingSubtitle': 'Review recent execution history and current system activity.',
  'runs.loading': 'Loading recent runs…',
  'runs.downSubtitle': 'Recent execution history is unavailable.',
  'runs.down': 'Unable to load run history.',
  'runs.emptySubtitle': 'Recent execution history and current activities.',
  'runs.empty.title': 'No runs yet',
  'runs.empty.body': 'There are no recent runs to display. Start one from the Targets view.',
  'runs.subtitle': 'The {count} most recent runs the API returns (at most 100).',
  'runs.filters': 'Filter runs',
  'runs.searchPlaceholder': 'run id, target, collector or error',
  'runs.allTargets': 'All targets',
  'runs.allStatuses': 'All statuses',
  'runs.anyTime': 'Any time',
  'runs.last24h': 'Last 24 hours',
  'runs.last7d': 'Last 7 days',
  'runs.noMatch.title': 'No runs match',
  'runs.noMatch.body': 'Clear a filter or widen the search to see more runs.',
  // target detail
  'target.subtitle': '{purpose} · authorisation: {authorization}',
  'target.workspace': 'Target workspace',
  'target.back': 'Back to targets',
  'target.loading': 'Loading target…',
  'target.down': 'Target “{targetId}” could not be loaded.',
  'target.enabled': 'Enabled',
  'target.schedule': 'Schedule (UTC cron)',
  'target.llm': 'LLM route',
  'target.risk': 'Risk',
  'target.peak': 'peak {peak} over {count} {runs}',
  'target.run': 'run',
  'target.runs': 'runs',
  'target.riskHistory': 'Risk history, oldest first',
  'target.runsTitle': 'Runs',
  'target.runsLoading': 'Loading runs…',
  'target.runsDown': "Unable to load this target's runs.",
  'target.noRuns.title': 'No runs yet',
  'target.noRuns.body': 'This target has not been collected yet. Use Start run above to collect it now.',
  'target.noMatch.title': 'No runs match',
  'target.noMatch.body': 'Clear the status filter to see every run of this target.',
  // run detail
  'runDetail.title': 'Run #{runId}',
  'runDetail.fallbackTitle': 'Run detail',
  'runDetail.subtitle': '{targetId} · started {started} · {duration}',
  'runDetail.loadingContext': 'Loading run context…',
  'runDetail.loading': 'Loading run…',
  'runDetail.down': 'Run #{runId} could not be loaded.',
  'runDetail.status': 'Status',
  'runDetail.collectors': 'Collectors',
  'runDetail.newObservables': 'New observables',
  'runDetail.sealed': 'Sealed',
  'runDetail.artefacts': 'Run artefacts',
  'runDetail.download': 'Download {artifact}',
  'runDetail.downloadFailed': 'The {artifact} could not be downloaded.',
  'runDetail.loadingArtifact': 'Loading {artifact}…',
  'runDetail.noArtifact.title': 'No {artifact} for this run',
  'runDetail.noArtifact.body': 'The artefact is not available (the run may have failed before producing it).',
  'runDetail.riskLevel': 'Risk level',
  'runDetail.summary': 'Summary',
  'runDetail.justification': 'Justification',
  'runDetail.newSince': 'New since the previous run',
  'runDetail.pivots': 'Suggested pivots',
  'runDetail.noEvidence': 'No qualified evidence for this run.',
  'runDetail.evidenceFilters': 'Filter evidence',
  'runDetail.evidencePlaceholder': 'title, URL, rationale',
  'runDetail.anyRelevance': 'Any relevance',
  'runDetail.anyCategory': 'Any category',
  'runDetail.noEvidenceMatch': 'No evidence matches the current filters.',
  'runDetail.noDelta': 'No net-new observables in this run.',
  'runDetail.deltaFilters': 'Filter observables',
  'runDetail.deltaPlaceholder': 'value',
  'runDetail.anyType': 'Any type',
  'runDetail.noDeltaMatch': 'No observables match the current filters.',
  'artifact.finding': 'finding',
  'artifact.evidence': 'evidence',
  'artifact.delta': 'delta',
  'artifact.report': 'report',
  'artifact.manifest': 'manifest',
  // identifier values (display labels only; the data keeps the English value)
  'value.pending': 'pending',
  'value.running': 'running',
  'value.success': 'success',
  'value.partial': 'partial',
  'value.failed': 'failed',
  'value.unknown': 'unknown',
  'value.low': 'low',
  'value.medium': 'medium',
  'value.high': 'high',
  'value.critical': 'critical',
  'value.ok': 'ok',
  'value.degraded': 'degraded',
  'value.offline': 'offline',
  'value.disabled': 'disabled',
} as const;

export type MessageKey = keyof typeof en;

const es: Record<MessageKey, string> = {
  appTitle: 'OSINT Orchestrator',
  appSubtitle: 'Panel del operador',
  skipToContent: 'Saltar al contenido',
  mainNavigation: 'Navegación principal',
  languageSwitcher: 'Idioma',
  'locale.es': 'Español',
  'locale.en': 'English',
  'nav.overview': 'Resumen',
  'nav.targets': 'Objetivos',
  'nav.runs': 'Corridas',
  forgetKey: 'Olvidar clave',
  checkingAccess: 'Comprobando el acceso a la API…',
  'unavailable.title': 'API no disponible',
  'unavailable.body': 'No se pudo contactar la API del orquestador.',
  'unavailable.bodyWithStatus': 'No se pudo contactar la API del orquestador (estado {status}).',
  'unavailable.bodyNetwork': 'No se pudo contactar la API del orquestador: la solicitud no obtuvo respuesta (error de red o servidor caído).',
  retry: 'Reintentar',
  'error.title': 'Algo salió mal.',
  'error.body': 'La interfaz encontró un error inesperado. Recargue la página para intentar de nuevo.',
  'state.unableToLoad': 'No se pudo cargar esta vista',
  eyebrow: 'Operaciones',
  'gate.eyebrow': 'Acceso del operador',
  'gate.title': 'Se requiere la clave de API',
  'gate.lede.before': 'Este panel lee la API del orquestador con la clave del operador (',
  'gate.lede.after': '). La clave queda en esta pestaña; marque “recordar” para conservarla en este dispositivo.',
  'gate.formTitle': 'Ingrese la clave de API',
  'gate.keyLabel': 'Clave de API',
  'gate.remember': 'Recordar en este navegador',
  'gate.help': 'Sin “recordar”, la clave se olvida al cerrar la pestaña.',
  'gate.submit': 'Usar clave',
  'gate.checking': 'Comprobando…',
  'gate.empty': 'Ingrese la clave de API.',
  'gate.rejected': 'La API rechazó esta clave.',
  'gate.unvalidated': 'No se pudo validar la clave. {reason}',
  'gate.unknownError': 'No se pudo usar esta clave.',
  'notFound.title': 'Página no encontrada',
  'notFound.subtitle': 'La ruta solicitada no existe en este panel.',
  'notFound.emptyTitle': 'Ninguna ruta coincide',
  'notFound.emptyBody': 'Use la navegación de arriba para volver a una vista disponible.',
  'run.accepted': 'Corrida #{runId} aceptada para {targetId}.',
  'run.failed': 'No se pudo iniciar la corrida.',
  'run.failed.disabled': 'No se pudo iniciar la corrida: el objetivo está deshabilitado.',
  'run.failed.inProgress': 'No se pudo iniciar la corrida: ya hay una corrida en curso para este objetivo.',
  'run.failed.notFound': 'No se pudo iniciar la corrida: el objetivo no existe.',
  'run.failed.unauthorized': 'No se pudo iniciar la corrida: la API rechazó la clave.',
  'run.failed.status': 'No se pudo iniciar la corrida (estado {status}).',
  'run.serverDetail': 'Detalle del servidor: {detail}',
  'run.start': 'Iniciar corrida',
  'run.running': 'En curso…',
  'run.startFor': ' para {targetId}',
  never: 'nunca',
  noRuns: 'sin corridas',
  yes: 'Sí',
  no: 'No',
  disabledSuffix: ' · deshabilitado',
  'count.of': '{visible} de {total}',
  clearFilters: 'Limpiar filtros',
  search: 'Buscar',
  soFar: 'hasta ahora',
  back: 'Volver',
  'col.target': 'Objetivo',
  'col.run': 'Corrida',
  'col.collectors': 'Colectores',
  'col.lastRun': 'Última corrida',
  'col.status': 'Estado',
  'col.risk': 'Riesgo',
  'col.peakRisk': 'Riesgo máximo',
  'col.newObservables': 'Observables nuevos',
  'col.started': 'Inicio',
  'col.elapsed': 'Transcurrido',
  'col.duration': 'Duración',
  'col.actions': 'Acciones',
  'col.category': 'Categoría',
  'col.relevance': 'Relevancia',
  'col.confidence': 'Confianza',
  'col.source': 'Fuente',
  'col.rationale': 'Justificación',
  'col.type': 'Tipo',
  'col.value': 'Valor',
  'overview.title': 'Resumen',
  'overview.loadingSubtitle': 'Comprobando el estado operativo actual.',
  'overview.loading': 'Cargando salud del servicio, objetivos y corridas…',
  'overview.downSubtitle': 'No se pudo contactar la API del orquestador.',
  'overview.down': 'Ni la comprobación de salud ni el inventario de objetivos respondieron. Verifique que la API esté en ejecución y accesible desde este navegador.',
  'overview.subtitle': 'Qué requiere atención: corridas activas, riesgo, fallos y cobertura de un vistazo.',
  'overview.kpis': 'Cifras clave',
  'overview.window': 'Las cifras basadas en corridas salen de las {count} corridas más recientes que devuelve la API (como máximo 100).',
  'kpi.activeRuns': 'Corridas activas',
  'kpi.activeRuns.caption': 'pendientes o en curso ahora',
  'kpi.runs24h': 'Corridas en 24 h',
  'kpi.runs24h.caption': 'iniciadas en el último día, dentro de las corridas cargadas',
  'kpi.successRate': 'Tasa de éxito',
  'kpi.successRate.caption': 'de {count} corridas terminadas cargadas',
  'kpi.medianRun': 'Duración mediana',
  'kpi.medianRun.caption': 'tiempo de completado, del inicio al estado final',
  'kpi.atRisk': 'Objetivos en riesgo',
  'kpi.atRisk.caption': 'último hallazgo alto o crítico',
  'kpi.coverage': 'Cobertura, 7 días',
  'kpi.coverage.caption': 'objetivos habilitados con una corrida esta semana, dentro de las corridas cargadas',
  'overview.targets': 'Objetivos por atención',
  'overview.trendsDown': 'Los niveles de riesgo no están disponibles ahora; la tabla muestra solo el estado de las corridas.',
  'overview.noTargets.title': 'No hay objetivos configurados',
  'overview.noTargets.body': 'Agregue un objetivo en targets.yaml y recargue el planificador; aparecerá aquí con sus corridas y su riesgo.',
  'overview.inventoryDown': 'El inventario de objetivos no está disponible.',
  'overview.active': 'Corridas activas',
  'overview.runsDown': 'El historial de corridas no está disponible.',
  'overview.nothingRunning.title': 'Nada en curso',
  'overview.nothingRunning.body': 'No hay corridas pendientes ni en curso. Inicie una desde la tabla de arriba; esta lista se actualiza sola mientras corre.',
  'overview.findings': 'Hallazgos recientes',
  'overview.findingsLoading': 'Cargando hallazgos…',
  'overview.findingsFailed': 'No se pudieron cargar {count} hallazgo(s).',
  'overview.noRuns.title': 'Todavía no hay corridas',
  'overview.noRuns.body': 'Los hallazgos aparecen aquí cuando una corrida termina con una síntesis del modelo.',
  'overview.goToTargets': 'Ir a objetivos',
  'overview.noFindings.title': 'Sin hallazgos en las últimas corridas',
  'overview.noFindings.body': 'Las corridas recientes terminaron sin síntesis (no hay modelo configurado o la corrida falló antes). Abra una corrida para ver su evidencia y su delta.',
  'overview.findingLink': 'Corrida #{runId} · {targetId}',
  'overview.newSince': '{count} nuevos desde la última corrida',
  'overview.health': 'Salud del servicio',
  'overview.healthDown': 'El endpoint de salud no respondió.',
  'targets.title': 'Objetivos',
  'targets.loadingSubtitle': 'Revise el conjunto de objetivos activos y su cobertura.',
  'targets.loading': 'Cargando objetivos…',
  'targets.downSubtitle': 'El inventario de objetivos no está disponible.',
  'targets.down': 'No se pudieron cargar los objetivos.',
  'targets.subtitle': 'El inventario de objetivos de este espacio de trabajo.',
  'targets.empty.title': 'No hay objetivos configurados',
  'targets.empty.body': 'Agregue un objetivo en targets.yaml y recargue el planificador para empezar a seguirlo.',
  'targets.filters': 'Filtrar objetivos',
  'targets.searchPlaceholder': 'id, dominio, propósito o colector',
  'targets.enabled': 'Habilitado',
  'targets.enabled.all': 'Todos',
  'targets.enabled.enabled': 'Solo habilitados',
  'targets.enabled.disabled': 'Solo deshabilitados',
  'targets.anyStatus': 'Cualquier estado',
  'targets.neverCollected': 'nunca recolectado',
  'targets.anyRisk': 'Cualquier riesgo',
  'targets.noMatch.title': 'Ningún objetivo coincide',
  'targets.noMatch.body': 'Limpie un filtro o amplíe la búsqueda para ver más objetivos.',
  'runs.title': 'Corridas',
  'runs.loadingSubtitle': 'Revise el historial reciente y la actividad actual del sistema.',
  'runs.loading': 'Cargando corridas recientes…',
  'runs.downSubtitle': 'El historial reciente no está disponible.',
  'runs.down': 'No se pudo cargar el historial de corridas.',
  'runs.emptySubtitle': 'Historial reciente y actividad actual.',
  'runs.empty.title': 'Todavía no hay corridas',
  'runs.empty.body': 'No hay corridas recientes para mostrar. Inicie una desde la vista de Objetivos.',
  'runs.subtitle': 'Las {count} corridas más recientes que devuelve la API (como máximo 100).',
  'runs.filters': 'Filtrar corridas',
  'runs.searchPlaceholder': 'id de corrida, objetivo, colector o error',
  'runs.allTargets': 'Todos los objetivos',
  'runs.allStatuses': 'Todos los estados',
  'runs.anyTime': 'Cualquier momento',
  'runs.last24h': 'Últimas 24 horas',
  'runs.last7d': 'Últimos 7 días',
  'runs.noMatch.title': 'Ninguna corrida coincide',
  'runs.noMatch.body': 'Limpie un filtro o amplíe la búsqueda para ver más corridas.',
  'target.subtitle': '{purpose} · autorización: {authorization}',
  'target.workspace': 'Espacio del objetivo',
  'target.back': 'Volver a objetivos',
  'target.loading': 'Cargando objetivo…',
  'target.down': 'No se pudo cargar el objetivo “{targetId}”.',
  'target.enabled': 'Habilitado',
  'target.schedule': 'Programación (cron UTC)',
  'target.llm': 'Ruta LLM',
  'target.risk': 'Riesgo',
  'target.peak': 'máximo {peak} en {count} {runs}',
  'target.run': 'corrida',
  'target.runs': 'corridas',
  'target.riskHistory': 'Historial de riesgo, de más antiguo a más reciente',
  'target.runsTitle': 'Corridas',
  'target.runsLoading': 'Cargando corridas…',
  'target.runsDown': 'No se pudieron cargar las corridas de este objetivo.',
  'target.noRuns.title': 'Todavía no hay corridas',
  'target.noRuns.body': 'Este objetivo aún no fue recolectado. Use Iniciar corrida arriba para recolectarlo ahora.',
  'target.noMatch.title': 'Ninguna corrida coincide',
  'target.noMatch.body': 'Limpie el filtro de estado para ver todas las corridas de este objetivo.',
  'runDetail.title': 'Corrida #{runId}',
  'runDetail.fallbackTitle': 'Detalle de corrida',
  'runDetail.subtitle': '{targetId} · inicio {started} · {duration}',
  'runDetail.loadingContext': 'Cargando el contexto de la corrida…',
  'runDetail.loading': 'Cargando corrida…',
  'runDetail.down': 'No se pudo cargar la corrida #{runId}.',
  'runDetail.status': 'Estado',
  'runDetail.collectors': 'Colectores',
  'runDetail.newObservables': 'Observables nuevos',
  'runDetail.sealed': 'Sellada',
  'runDetail.artefacts': 'Artefactos de la corrida',
  'runDetail.download': 'Descargar {artifact}',
  'runDetail.downloadFailed': 'No se pudo descargar {artifact}.',
  'runDetail.loadingArtifact': 'Cargando {artifact}…',
  'runDetail.noArtifact.title': 'Sin {artifact} para esta corrida',
  'runDetail.noArtifact.body': 'El artefacto no está disponible (la corrida pudo haber fallado antes de producirlo).',
  'runDetail.riskLevel': 'Nivel de riesgo',
  'runDetail.summary': 'Resumen',
  'runDetail.justification': 'Justificación',
  'runDetail.newSince': 'Nuevo desde la corrida anterior',
  'runDetail.pivots': 'Pivotes sugeridos',
  'runDetail.noEvidence': 'Sin evidencia calificada en esta corrida.',
  'runDetail.evidenceFilters': 'Filtrar evidencia',
  'runDetail.evidencePlaceholder': 'título, URL, justificación',
  'runDetail.anyRelevance': 'Cualquier relevancia',
  'runDetail.anyCategory': 'Cualquier categoría',
  'runDetail.noEvidenceMatch': 'Ninguna evidencia coincide con los filtros actuales.',
  'runDetail.noDelta': 'Sin observables nuevos en esta corrida.',
  'runDetail.deltaFilters': 'Filtrar observables',
  'runDetail.deltaPlaceholder': 'valor',
  'runDetail.anyType': 'Cualquier tipo',
  'runDetail.noDeltaMatch': 'Ningún observable coincide con los filtros actuales.',
  'artifact.finding': 'hallazgo',
  'artifact.evidence': 'evidencia',
  'artifact.delta': 'delta',
  'artifact.report': 'informe',
  'artifact.manifest': 'manifiesto',
  'value.pending': 'pendiente',
  'value.running': 'en curso',
  'value.success': 'exitosa',
  'value.partial': 'parcial',
  'value.failed': 'fallida',
  'value.unknown': 'desconocido',
  'value.low': 'bajo',
  'value.medium': 'medio',
  'value.high': 'alto',
  'value.critical': 'crítico',
  'value.ok': 'ok',
  'value.degraded': 'degradado',
  'value.offline': 'fuera de línea',
  'value.disabled': 'deshabilitado',
};

export const translations: Record<Locale, Record<MessageKey, string>> = { es, en };

export type Vars = Record<string, string | number>;

export function format(template: string, vars?: Vars): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (match, name: string) => (name in vars ? String(vars[name]) : match));
}

export function translate(locale: Locale, key: MessageKey, vars?: Vars): string {
  return format(translations[locale][key] ?? translations.en[key], vars);
}

/** Display label of a persisted identifier (status, risk, relevance); the raw value when unknown. */
export function translateValue(locale: Locale, value: string): string {
  const key = `value.${value}` as MessageKey;
  return key in translations.en ? translations[locale][key] : value;
}

function isLocale(value: unknown): value is Locale {
  return typeof value === 'string' && (locales as readonly string[]).includes(value);
}

export function detectLocale(): Locale {
  try {
    const stored = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    if (isLocale(stored)) return stored;
  } catch {
    // Storage unavailable: fall through to the browser language.
  }
  const browser = typeof navigator !== 'undefined' ? navigator.language?.slice(0, 2).toLowerCase() : '';
  return isLocale(browser) ? browser : defaultLocale;
}

type LocaleContextValue = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: (key: MessageKey, vars?: Vars) => string;
  tv: (value: string) => string;
};

const LocaleContext = createContext<LocaleContextValue | undefined>(undefined);

/** Keep <html lang> in step so screen readers, telemetry and CSS :lang() see the operator's language. */
function applyDocumentLanguage(locale: Locale) {
  if (typeof document !== 'undefined') {
    document.documentElement.lang = locale;
  }
}

export function LocaleProvider({ children, initialLocale }: { children: ReactNode; initialLocale?: Locale }) {
  // Resolved and applied during the first render, before any child effect
  // (app_loaded telemetry reads the document language) can run.
  const [locale, setLocaleState] = useState<Locale>(() => {
    const resolved = initialLocale ?? detectLocale();
    applyDocumentLanguage(resolved);
    return resolved;
  });

  useEffect(() => {
    applyDocumentLanguage(locale);
  }, [locale]);

  const setLocale = useCallback((next: Locale) => {
    applyDocumentLanguage(next);
    setLocaleState(next);
    try {
      window.localStorage.setItem(LOCALE_STORAGE_KEY, next);
    } catch {
      // Storage unavailable: the choice lasts for this page only.
    }
  }, []);

  const value = useMemo<LocaleContextValue>(
    () => ({
      locale,
      setLocale,
      t: (key, vars) => translate(locale, key, vars),
      tv: (raw) => translateValue(locale, raw),
    }),
    [locale, setLocale],
  );

  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>;
}

export function useLocale(): LocaleContextValue {
  const context = useContext(LocaleContext);
  if (!context) {
    throw new Error('useLocale must be used within LocaleProvider');
  }
  return context;
}
