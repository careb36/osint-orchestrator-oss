# ADR-005: Claves de API estáticas, observabilidad estructurada y despliegue de instancia única

> 🇬🇧 [English](ADR-005-api-auth-and-single-instance.md)

**Estado:** Aceptada
**Fecha:** 2026-09-08
**Fase:** 5

> **Enmendada por:** [ADR-006](ADR-006-oidc-proxy-es.md) — la
> alternativa "OAuth 2 / OIDC" rechazada aquí se materializó como un overlay
> de compose *opcional* para operadores humanos; la autenticación por clave de
> API para clientes máquina no cambia.

## Contexto

Las fases 0–4 produjeron un orquestador capaz de lanzar recolecciones contra
objetivos autorizados, leer sus hallazgos y enviar alertas — todo por una API
HTTP sin autenticación, con logs de texto plano y sin métricas. Eso sirve en
una laptop detrás de `docker compose`; no sirve en una red compartida ni en
un clúster. La Fase 5 tiene que hacer el servicio desplegable por un equipo
de operaciones sin cambiar lo que hace.

Había que resolver tres preguntas:

1. **¿Cómo se autentican los clientes?** Los clientes son operadores y
   automatizaciones (un cron, un pipeline de CI, un playbook de SOAR), no
   usuarios finales. La plataforma de referencia, OpenCTI, ya tiene sus
   propios usuarios, roles y tokens.
2. **¿Qué forma tienen los logs y las métricas?** Un recolector de logs
   necesita una forma estable; quien está de guardia necesita responder
   "¿está corriendo, va atrasado, está fallando?" desde un tablero, no con
   `grep`.
3. **¿Cómo corre en Kubernetes?** El estado operativo es SQLite y el
   scheduler es APScheduler dentro del proceso. Ambas fueron decisiones
   deliberadas (ADR-001: monolito modular, sin infraestructura extra) y
   ambas asumen un único proceso.

## Decisión

### Autenticación: claves de API estáticas compartidas

- `ORCHESTRATOR_API_KEY` contiene una o más claves (separadas por coma). Una
  petición presenta una como `X-API-Key: <clave>` o
  `Authorization: Bearer <clave>`.
- Todos los endpoints de datos exigen clave. `GET /health` y `GET /metrics`
  no: los probes y los scrapers no son clientes de la API y ninguno de los
  dos devuelve datos de objetivos.
- Una `ORCHESTRATOR_API_KEY` vacía desactiva la autenticación y registra una
  advertencia una vez al arrancar. El valor por defecto sigue abierto para
  que `docker compose up` en una laptop siga funcionando; un despliegue de
  producción debe fijar una clave, y las notas de instalación del chart de
  Helm lo dicen bien claro.
- Las claves se comparan en tiempo constante y se verifican todas las
  configuradas, así una petición rechazada tarda lo mismo sin importar qué
  posición habría coincidido.
- Los detalles de error se localizan como cualquier otro error de la API
  (ADR-004).

Alternativas descartadas:

- **OAuth 2 / OIDC.** Es la respuesta correcta para navegadores y humanos;
  no encaja con cron ni playbooks, y agrega un proveedor de identidad a un
  stack que ya tiene cinco servicios. Se revisará si algún día se construye
  una interfaz sobre esta API.
  *(Revisada: se entregó una consola mínima de operador y el ADR-006 añade
  OIDC como overlay opcional de front door — el contrato de clave de API para
  clientes máquina queda intacto.)*
- **Cuentas por usuario en el orquestador.** Duplicaría el RBAC de OpenCTI
  con menos capacidades. La autorización sobre *objetivos* no es un problema
  de control de acceso: es el campo `authorization` de `targets.yaml`,
  registrado en cada ejecución.
- **mTLS.** Excelente entre servicios, incómodo para una persona con `curl`.
  Nada impide ponerlo delante (un ingress o una malla de servicios).

### Observabilidad: logs JSON, ids de petición, Prometheus

- `ORCHESTRATOR_LOG_FORMAT=json` emite un objeto JSON por línea (`ts`,
  `level`, `logger`, `msg`, más cualquier campo `extra=` como `target_id`,
  `run_id`, `collector`). `text` sigue siendo el valor por defecto para una
  terminal.
- Cada petición HTTP recibe un id (el `X-Request-ID` que envíe el cliente o
  uno generado), devuelto en la respuesta y estampado en cada línea de log
  emitida mientras se atiende. Las ejecuciones en segundo plano del scheduler
  registran `-`.
- `GET /metrics` sirve métricas Prometheus: peticiones HTTP y latencia por
  *plantilla de ruta*, ejecuciones por estado final, resultados y duraciones
  por recolector, resultados de ingesta en OpenCTI, estado de la síntesis,
  envíos de alertas y cantidad de jobs programados. Los valores de las
  etiquetas están acotados a propósito — nunca el valor de un observable, un
  id de ejecución ni un texto de error.
- Sin biblioteca de logging ni SDK de OpenTelemetry: el formateador son
  cuarenta líneas y `prometheus_client` es la única dependencia agregada. Las
  trazas pueden llegar después mediante un collector de OTel sin tocar la
  aplicación, si se propaga el id de petición.

### Despliegue: un chart de Helm para una réplica

- `deploy/helm/osint-orchestrator` despliega solo el orquestador. OpenCTI,
  SpiderFoot y Ollama tienen sus propios charts y se referencian por URL.
- **`replicaCount` es 1 y la estrategia es `Recreate`.** SQLite en un volumen
  `ReadWriteOnce` y un scheduler en proceso no escalan horizontalmente: dos
  réplicas ejecutarían dos veces cada cron y corromperían la base. Es la
  consecuencia honesta de ADR-001 y ADR-003 — el orquestador es un
  coordinador liviano, el estado pesado vive en OpenCTI — y un único pod
  alcanza para la carga (un puñado de objetivos, unas pocas ejecuciones al
  día).
- Los secretos vienen de un Secret (idealmente uno existente gestionado por
  External Secrets / Sealed Secrets), la configuración de un ConfigMap,
  `targets.yaml` de otro ConfigMap, y una anotación con checksum reinicia el
  pod cuando cambian.

## Consecuencias

- La API puede exponerse detrás de un ingress una vez fijada una clave; el
  valor por defecto sigue siendo cómodo para desarrollo. Los operadores deben
  tratar la clave como cualquier otra credencial (la rotación se soporta
  listando la clave vieja y la nueva juntas durante el cambio).
- Los tableros y las alertas pueden construirse sobre las métricas
  `osint_orchestrator_*` sin parsear logs. Los nombres de las métricas son
  parte del contrato con el operador: renombrar una es un cambio incompatible
  y se anota en el README.
- El escalado horizontal queda explícitamente fuera de alcance. El disparador
  para revisar esta ADR es concreto: más objetivos de los que un pod puede
  recolectar dentro de su ventana de programación. Llegado ese punto el
  camino es una base compartida (PostgreSQL, que SQLModel ya soporta) y mover
  el scheduler a un disparador externo o con elección de líder — no una
  reescritura.
- CI valida el chart con `helm lint` y `helm template` cuando la herramienta
  está disponible; el chart sigue las convenciones de `helm create` para que
  cualquiera que haya visto uno lo lea sin esfuerzo.
