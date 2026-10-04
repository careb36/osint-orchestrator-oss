# Presentación ejecutiva: Orquestador OSINT para monitoreo continuo

> 🇬🇧 [English](executive-project-presentation.md)

**Última revisión:** 2026-09-17
**Audiencia:** Dirección, Contaduría, Cumplimiento LA/FT, Legales.
**Tipo de documento:** Explicación (Diátaxis) — no es un manual operativo.

> **Alcance y descargo.** Este documento describe una herramienta de apoyo a
> procesos de debida diligencia y monitoreo. **No constituye asesoramiento
> legal**, no sustituye el criterio profesional del Oficial de Cumplimiento ni
> de la Contaduría, y no exime de ninguna obligación prevista en la normativa
> uruguaya de prevención de lavado de activos y financiamiento del terrorismo
> (LA/FT).

---

## 1) Resumen ejecutivo

El proyecto **OSINT Orchestrator** automatiza la recolección ordenada de
información de fuentes abiertas (OSINT, por *Open Source Intelligence*) sobre
activos digitales autorizados —por ejemplo, el dominio web de una empresa— y
la convierte en evidencia trazable, fechada y auditable.

En una frase: **el sistema mira de forma continua y documentada lo que hoy un
analista miraría a mano, y deja constancia de todo lo que vio, cuándo y por
qué autorización.**

- **Problema que resuelve:** la debida diligencia y el monitoreo continuo se
  hacen hoy de forma manual, dispersa y difícil de evidenciar ante una
  auditoría o ante el regulador.
- **Qué aporta:** corridas programadas, resultados normalizados en un formato
  estándar internacional (STIX 2.1), un repositorio único de hallazgos
  (OpenCTI), informes diarios en español, alertas y una pista de auditoría
  completa por ejecución.
- **Qué se necesita:** un servidor con ≥16 GB de RAM, definición de objetivos
  autorizados y una rutina diaria de revisión de 15–20 minutos (manual
  operativo ya escrito para Contadores y Abogados).
- **Costo de licencias:** cero. Todo el stack es software de código abierto
  (licencia MIT la parte desarrollada por nosotros).

## 2) Problema y oportunidad

Los equipos de cumplimiento y auditoría necesitan, entre otras cosas:

1. **Debida diligencia del cliente (DDC)** con enfoque basado en riesgos,
   incluida la DDC reforzada cuando el riesgo lo amerita.
2. **Monitoreo continuo**: el perfil de riesgo de un cliente no es una foto,
   cambia con el tiempo.
3. **Evidencia documentada**: registros y documentación respaldante que
   puedan ponerse a disposición del supervisor cuando lo requiera.

En la práctica, parte de esa información está en fuentes abiertas: el sitio
web del cliente, sus subdominios, sus direcciones IP, sus cuentas oficiales en
redes sociales, menciones públicas. Relevarlas a mano es lento, inconsistente
entre analistas y, sobre todo, **difícil de probar**: no queda un registro
sistemático de qué se consultó, cuándo, con qué resultado y con qué
autorización.

La oportunidad es automatizar ese relevamiento manteniendo el control: cada
corrida queda registrada con su autorización, su propósito, su resultado y su
responsable de revisión.

## 3) Qué es el sistema (en lenguaje claro)

| Concepto | Qué significa |
| --- | --- |
| **Objetivo (target)** | Un activo digital autorizado para monitoreo (p. ej. `empresa.com.uy`). Cada objetivo exige dos campos obligatorios: `authorization` (quién autorizó y cuándo) y `purpose` (para qué se monitorea). |
| **Corrida (run)** | Una ejecución completa del relevamiento sobre un objetivo. Termina en `success` (todo funcionó), `partial` (hubo resultados con fallas parciales) o `failed` (sin resultados útiles). |
| **Observable** | Un dato concreto hallado: un subdominio, una IP, un correo, una cuenta de red social. |
| **Delta** | Lo **nuevo** respecto de la corrida anterior. Es el dato de mayor valor operativo: qué cambió desde la última vez que miramos. |
| **Finding** | Resumen del estado y nivel de riesgo de la corrida (`low`, `medium`, `high`, `critical`, `unknown`), con justificación y próximos pasos sugeridos. |
| **Reporte diario** | Documento Markdown (y PDF) por objetivo y por día, con trazabilidad, inventario completo, delta, relaciones y errores. |
| **Alerta** | Notificación automática (webhook o correo) cuando aparecen observables nuevos o el riesgo supera el umbral configurado. |

El sistema **solo consulta fuentes públicas** y **solo contra objetivos
listados y autorizados** en un archivo de configuración. No incluye ninguna
capacidad de intrusión, explotación o autenticación contra sistemas de
terceros. La política de uso autorizado es explícita y está documentada en el
README y en `SECURITY.es.md`.

## 4) La orquestación: cómo funciona y por qué importa

"Orquestar" es coordinar varias herramientas independientes para que trabajen
como un solo proceso confiable. El flujo de una corrida:

```text
 targets.yaml (objetivos autorizados)
        │  programación (cron) o disparo manual por API
        ▼
 ┌─────────────────────────────────────────────────┐
 │                ORQUESTADOR                      │
 │                                                 │
 │ 1. RECOLECTAR   OpenOSINT · SpiderFoot ·        │
 │                 SocialOSINT (opcional)          │
 │        ▼                                        │
 │ 2. NORMALIZAR   todo a STIX 2.1 (estándar       │
 │                 internacional de                │
 │                 ciberinteligencia)              │
 │        ▼                                        │
 │ 3. INGESTAR     a OpenCTI (fuente única de      │
 │                 verdad) — con cola de reintento │
 │        ▼                                        │
 │ 4. SINTETIZAR   lectura de riesgo asistida por  │
 │                 IA (LLM), siempre etiquetada    │
 │        ▼                                        │
 │ 5. REPORTAR     report.md + PDF + delta +       │
 │                 bundle STIX por corrida         │
 │        ▼                                        │
 │ 6. ALERTAR      webhook firmado / correo, con   │
 │                 cola de reintentos y DLQ        │
 └─────────────────────────────────────────────────┘
```

Por qué la orquestación —y no una herramienta suelta— es lo valioso para
gestión:

- **Fuente única de verdad.** Todos los hallazgos convergen en OpenCTI, con
  identificadores deterministas: el mismo dato observado dos veces es el mismo
  objeto, no un duplicado. No hay planillas paralelas.
- **Nada se pierde en silencio.** Si OpenCTI no está disponible, el paquete de
  hallazgos queda en una **cola persistente (outbox)** y se reintenta solo con
  espera creciente. Si una alerta no se entrega, pasa por reintentos y, si
  fallan todos, a una **cola de muertos (DLQ)** visible y reprocesable
  manualmente. Los estados `partial` y `failed` se registran: una corrida con
  problemas nunca parece exitosa.
- **Cada punta del proceso es auditable.** Identificador de corrida, fechas
  UTC, autorización y propósito impresos en el reporte, estado por herramienta,
  errores textuales, y firma digital (HMAC-SHA256) en las alertas webhook.
- **Trabajo acotado por diseño.** Los recolectores tienen presupuestos duros
  (profundidad máxima, cantidad máxima de consultas, tiempo límite). Una
  corrida programada no puede expandirse sin control sobre infraestructura de
  terceros.
- **Un solo operador alcanza.** El proceso completo es automático; la persona
  revisa resultados y decide, no ejecuta herramientas.

## 5) Aplicabilidad en prevención de LA/FT (marco uruguayo)

> Esta sección describe el **contexto normativo** en el que la herramienta
> puede ser útil. La interpretación de la normativa y su aplicación al caso
> concreto es responsabilidad exclusiva del Oficial de Cumplimiento y de los
> profesionales del estudio.

Marco de referencia (verificado a septiembre de 2026):

- **Ley N° 19.574** (20/12/2017), *Ley Integral contra el Lavado de Activos*,
  reglamentada por el **Decreto N° 379/018**, y modificada por la **Ley
  N° 20.469** (19/03/2026). Define los sujetos obligados (art. 13), el
  enfoque basado en riesgos y las obligaciones de debida diligencia,
  registro y reporte.
- **La autoridad nacional de supervisión ALA/CFT de los sujetos obligados no
  financieros** supervisa un sector que incluye a contadores, abogados y
  escribanos (capítulo V del Decreto 379/018), y exige la conservación y puesta
  a disposición de registros y documentación respaldante.
- **La unidad nacional de inteligencia financiera** recepta los reportes de
  operaciones sospechosas (ROS).
- **Ley N° 19.749** (2019): financiamiento del terrorismo y sanciones
  financieras dirigidas.
- **Ley N° 20.075** (2022): pautas de sanción para sujetos obligados no
  financieros ante incumplimientos preventivos.

Fuentes oficiales consultadas el 2026-09-17:

- [Ley N° 19.574, texto actualizado (IMPO)](https://www.impo.com.uy/bases/leyes/19574-2017), en especial arts. 13–16.
- [Decreto N° 379/018, texto actualizado (IMPO)](https://www.impo.com.uy/bases/decretos/379-2018), en especial arts. 3–17.
- [Ley N° 20.469 (IMPO)](https://www.impo.com.uy/bases/leyes/20469-2026), modificativa de la Ley N° 19.574.
- La normativa vigente de la autoridad supervisora, publicada en el portal
  oficial del Estado.

Dónde encaja la herramienta (y dónde no):

| Proceso de cumplimiento | Aporte del orquestador | Límite |
| --- | --- | --- |
| Debida diligencia y DDC reforzada | Relevamiento documentado y reproducible de la huella digital del cliente/contraparte (dominios, IPs, correos, cuentas sociales oficiales) como **insumo** del legajo | No identifica beneficiarios finales ni reemplaza fuentes registrales |
| Monitoreo continuo basado en riesgo | Corridas programadas (cron) con **delta**: qué apareció o cambió desde la última revisión; alertas por umbral de riesgo | El nivel de riesgo que calcula la IA es orientativo y debe ser validado por el analista |
| Evidencia para auditoría y supervisor | Reportes fechados con `run_id`, autorización y propósito por objetivo; historial conservado por política de retención configurable | **Los 90 días por defecto son operativos, no regulatorios.** Para sujetos obligados alcanzados, el art. 15 del Decreto 379/018 establece un mínimo de cinco años. Debe configurarse un plazo compatible o archivarse la evidencia en almacenamiento externo controlado, según revisión profesional |
| Adverse media / noticias adversas | Análisis asistido por IA de cuentas sociales asociadas (SocialOSINT), almacenado **etiquetado como no verificado** | No es un servicio de screening de listas (PEP/sanciones); para eso existen proveedores especializados |

**Regla de uso:** el sistema produce insumos y evidencia de proceso. Las
decisiones de cumplimiento —clasificación de riesgo, reporte de operación
sospechosa, continuidad de la relación comercial— son siempre humanas,
fundamentadas y registradas según los procedimientos internos.

## 6) Control interno y auditabilidad

Desde la óptica de control interno, el sistema incorpora por diseño:

- **Documentación:** cada corrida genera artefactos fechados en
  `daily_reports/AAAA-MM-DD/<objetivo>/` (reporte, bundle STIX, delta, PDF
  opcional) más un índice diario ejecutivo. El filesystem por sí solo no
  aporta inmutabilidad ni almacenamiento WORM.
- **Trazabilidad:** identificador de correlación por petición HTTP, logs
  estructurados (JSON) con fecha UTC, y estados de corrida persistidos en base
  de datos.
- **Autorización explícita:** no existe corrida sin objetivo, ni objetivo sin
  `authorization` y `purpose` escritos; ambos se imprimen en cada reporte.
- **Segregación de funciones:** quien configura objetivos (con autorización
  escrita) no debería ser la única persona que revisa corridas o decide sobre
  hallazgos; la asignación de roles sigue siendo un control organizacional.
- **Cadena de custodia:** cada corrida registra entradas, fechas, resultados
  de recolectores y artefactos. La preservación probatoria y las aprobaciones
  deben seguir el procedimiento controlado de la organización.
- **Acceso:** API protegida por clave (con comparación en tiempo constante y
  rotación sin corte) y, opcionalmente, login nominativo de operadores vía
  Keycloak (OIDC), que deja auditoría de quién inició sesión.
- **Retención:** purga automática configurable de corridas e informes
  antiguos; la memoria de "ya visto" nunca se borra, para que el delta sea
  confiable.

## 7) Riesgos y límites del sistema

| Riesgo | Mitigación incorporada |
| --- | --- |
| Uso contra objetivos no autorizados | Campos `authorization`/`purpose` obligatorios; política de uso autorizado en README y SECURITY; el sistema no incluye capacidades ofensivas |
| "Alucinaciones" de la IA en el finding | La síntesis LLM es un resumen orientativo; los observables son datos crudos verificables; el análisis de redes sociales se etiqueta *no verificado*; el nivel de riesgo siempre requiere validación humana |
| Corrida con fallas parciales tomada como válida | Estados `partial`/`failed` explícitos; no se deben basar decisiones en una corrida `failed` |
| Fuga de datos sensibles en alertas | Opción `include_values: false` por objetivo (envía solo conteos y tipos); webhooks autenticados con HMAC-SHA256 |
| Alteración posterior de reportes | El sistema no firma ni bloquea los archivos generados. Para valor probatorio reforzado, exportar a almacenamiento versionado/WORM y registrar hashes SHA-256 conforme a la política interna |
| Exposición de la API | Clave obligatoria en producción (avisa si está vacía), front door OIDC opcional, métricas y health sin datos de objetivos |
| Privacidad / términos de plataformas | SocialOSINT usa APIs oficiales, es opt-in por objetivo y advierte sobre las restricciones de X/Twitter |
| Dependencia de un solo servidor | Decisión arquitectónica documentada (instancia única, ADR-005); el estado pesado vive en OpenCTI; backups del volumen SQLite + reportes |

## 8) Costo y esfuerzo operativo

- **Infraestructura:** un servidor (físico, virtual o nube) con ≥16 GB de RAM
  (32 GB holgado), ≥4 núcleos y ≥50 GB de disco. Docker como único
  requisito de software.
- **Licencias:** 0 USD. Stack 100 % open source (OpenCTI, MISP opcional,
  SpiderFoot, Keycloak; el orquestador es MIT).
- **Servicios de IA opcionales:** con Ollama local, la síntesis por IA no
  tiene costo ni envía datos fuera del servidor; con proveedores nube
  (Anthropic/OpenAI) hay costo por uso y transferencia de datos a un tercero
  (decisión a documentar).
- **Operación diaria:** verificar corridas, priorizar riesgo alto/crítico y
  registrar las decisiones humanas resultantes en el flujo de gestión de
  casos de la organización.
- **Puesta en marcha:** `docker compose up -d`, copiar dos archivos de
  configuración de ejemplo y cargar objetivos autorizados. El mantenimiento
  de esquema de base de datos es automático en cada arranque.

## 9) Estado actual y fases

| Fase | Estado | Contenido |
| --- | --- | --- |
| 0 | ✅ | Arquitectura documentada (ADRs), CI, stack Docker, health check |
| 1 | ✅ | Recolector OpenOSINT → normalizador STIX → ingesta OpenCTI |
| 2 | ✅ | Recolector SpiderFoot, programación cron, reportes diarios |
| 3 | ✅ | Síntesis LLM por objetivo (Ollama / Anthropic / OpenAI) |
| 4a | ✅ | Alertas webhook + correo con reintentos y DLQ |
| 4b | ✅ | SocialOSINT (opt-in) + stack MISP real con conector oficial |
| 5 | ✅ | Autenticación API, logs JSON, métricas Prometheus, chart de Kubernetes, consola web del operador |
| — | ✅ | Front door OIDC opcional (Keycloak + oauth2-proxy, ADR-006) |

El sistema está **funcional de punta a punta**: recolecta, normaliza, ingesta,
sintetiza, reporta, alerta y se despliega tanto en Docker Compose como en
Kubernetes. Su suite automatizada y los controles de calidad de CI protegen
los contratos principales.

## 10) Anexo: documentos relacionados

- [README del proyecto (ES)](../../README.es.md) — instalación y operación técnica
- [Política de seguridad](../../SECURITY.es.md) — uso autorizado y endurecimiento
- Decisiones de arquitectura: [ADR-003 (OpenCTI como fuente única)](../adr/ADR-003-opencti-as-store-es.md), [ADR-004 (idiomas)](../adr/ADR-004-language-policy-es.md), [ADR-005 (auth e instancia única)](../adr/ADR-005-api-auth-and-single-instance-es.md), [ADR-006 (front door OIDC)](../adr/ADR-006-oidc-proxy-es.md)

---

*Los términos técnicos persistidos (`success`, `partial`, `risk_level`) se
mantienen en inglés por convención (ADR-004).*
