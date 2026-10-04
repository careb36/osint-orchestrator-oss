# OSINT Orchestrator

> 🇬🇧 [English](README.md)

Orquesta herramientas OSINT de código abierto — **OpenOSINT**, **SpiderFoot** y, como opt-in, **OWASP SocialOSINT** y **OWASP Amass** — normaliza los hallazgos a **STIX 2.1** y los ingesta en **OpenCTI** como única fuente de verdad.

> **Decisión arquitectónica:** monolito modular → microservicios sólo cuando un módulo necesite escalar de forma independiente. Véase [`docs/adr/`](docs/adr/).

**Contenido** — [Uso autorizado](#uso-autorizado) · [Arquitectura](#arquitectura) · [Hardware](#requisitos-de-hardware) · [Inicio rápido](#inicio-rápido) · [MISP](#misp) · [SocialOSINT](#socialosint) · [Amass](#amass) · [Configuración](#configuración) · [API](#api) · [Objetivos](#configuración-de-objetivos) · [Idioma](#idioma) · [Reportes](#reportes-fase-2) · [Alertas](#alertas-fase-4a) · [Retención](#retención) · [Autenticación](#autenticación-de-la-api-fase-5) · [Observabilidad](#observabilidad-fase-5) · [Guías de negocio](#guías-de-negocio) · [Kubernetes](#kubernetes-fase-5) · [Desarrollo](#desarrollo) · [Migraciones](#migraciones-de-base-de-datos) · [Diagnóstico](#diagnóstico) · [Fases](#fases) · [ADRs](#decisiones-arquitectónicas)

---

## Uso autorizado

Este orquestador lanza reconocimiento contra lo que usted liste en
`targets.yaml`. SpiderFoot en particular hace peticiones DNS, TLS y HTTP
reales contra el objetivo: esta no es una herramienta puramente pasiva.

- Añada únicamente objetivos que le pertenezcan o para los que tenga
  **autorización escrita**.
- `authorization` y `purpose` son **obligatorios** en cada objetivo. No son
  decoración: ambos se escriben en el informe de cada ejecución y quedan como
  pista de auditoría de por qué se realizó esa recolección.
- `targets.yaml` no está cifrado y no es un almacén de secretos: las
  credenciales van en `.env`.
- Los payloads de alerta llevan valores de observables (dominios, direcciones
  IP, correos) salvo que ponga `include_values: false` en el objetivo. Tenga
  en cuenta dónde los almacena el canal receptor.

El repositorio no incluye nada que explote, autentique contra, o interactúe de
cualquier otro modo con un objetivo más allá de la recolección de fuentes
públicas.

---

## Arquitectura

```text
              targets.yaml  ·  API REST  ·  cron (APScheduler)
                                │
   ┌────────────────────────────▼─────────────────────────────┐
   │                  orchestrator  (FastAPI)                 │
   │  collectors/ → normalizer/ → sinks/ → reports/ → alerts/ │
   └───┬──────────────┬───────────────┬────────────┬──────────┘
       │              │               │            │
       ▼              ▼               ▼            │  pycti
┌─────────────┐ ┌────────────┐ ┌─────────────┐     │  (bundles STIX 2.1)
│  OpenOSINT  │ │ SpiderFoot │ │ SocialOSINT │     ▼
│ (en proceso)│ │ (HTTP API) │ │ Amass (opt) │  ┌───────────┐  conector   ┌──────┐
└─────────────┘ └────────────┘ └─────────────┘  │  OpenCTI  │◄───────────►│ MISP │
                                                │ ES·Redis· │  (Fase 4b)  └──────┘
                                                │ RabbitMQ· │
                                                │   MinIO   │
                                                └───────────┘
```

Una ejecución, de principio a fin: el scheduler (o `POST /targets/{id}/run`)
reparte el trabajo entre los recolectores habilitados, cada uno devuelve
hallazgos crudos; `normalizer/` los convierte en un único bundle STIX 2.1 con
ids deterministas; `sinks/opencti.py` lo envía mediante pycti; los observables
no vistos antes para ese objetivo se marcan como nuevos; `synthesizer/` pide a
un LLM una lectura de riesgo; `reports/` escribe los artefactos Markdown y STIX
del día; `alerts/` notifica si las reglas del objetivo lo piden.

**MISP** se integra a través del [conector oficial OpenCTI↔MISP](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/misp), no mediante código propio.

---

## Requisitos de hardware

> ⚠️ **OpenCTI requiere recursos considerables.** Verifique que su servidor cumple estos requisitos antes de desplegar.

Fuente: [OpenCTI-Platform/docker](https://github.com/OpenCTI-Platform/docker):

| Componente | RAM mínima |
| --- | --- |
| Elasticsearch heap (`ELASTIC_MEMORY_SIZE`) | **4 GB** (por defecto) |
| Plataforma OpenCTI (Node.js, `--max-old-space-size=8096`) | **8 GB** |
| Redis | ~256 MB |
| RabbitMQ | ~256 MB |
| MinIO | ~256 MB |
| Workers (×2) | ~512 MB |
| SpiderFoot | ~512 MB |
| Orchestrator | ~256 MB |
| **Total (núcleo)** | **≥ 16 GB** (32 GB recomendado) |
| Stack MISP (`-f docker-compose.misp.yml --profile misp`) | +1,6 GB adicionales |
| Servicio SocialOSINT (`--profile socialosint`) | +512 MB adicionales |
| Engine de Amass (`--profile amass`) | +256 MB adicionales (más con fuerza bruta) |

Requisitos adicionales del sistema operativo:

```bash
# Elasticsearch requiere vm.max_map_count ≥ 262144
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

**CPU:** ≥ 4 núcleos (Elasticsearch es intensivo en CPU durante la indexación).  
**Disco:** ≥ 50 GB (datos de Elasticsearch + objetos de MinIO).

---

## Inicio rápido

### Requisitos previos

- Docker Engine ≥ 24 y Docker Compose v2
- RAM del host ≥ 16 GB (véase arriba)
- `vm.max_map_count=262144` configurado en el host

### 1. Clonar y configurar

```bash
git clone https://github.com/careb36/osint-orchestrator-oss.git
cd osint-orchestrator

cp .env.example .env
# Editar .env — establecer contraseñas y generar OPENCTI_ADMIN_TOKEN:
#   python -c "import uuid; print(uuid.uuid4())"

cp targets.example.yaml targets.yaml
# Editar targets.yaml — añadir los objetivos autorizados
```

### 2. Arrancar el stack

```bash
docker compose up -d
```

Servicios iniciados:

- OpenCTI en <http://localhost:8080> (credenciales del archivo `.env`), junto con
  su `worker` (×2) y los conectores integrados `connector-import-file-stix` /
  `connector-opencti`, apoyados en Elasticsearch, Redis, RabbitMQ y MinIO
- SpiderFoot en <http://localhost:5001> (construido localmente desde fuente, `spiderfoot:local`)
- API del Orchestrator en <http://localhost:8000> (`orchestrator:8000` en la red de Docker)

> **No se incluye ningún servicio LLM.** Los valores por defecto
> `LLM_PROVIDER=ollama` / `LLM_BASE_URL=http://ollama:11434` esperan un endpoint
> de Ollama en la red de Docker. Sin él, la síntesis se omite o se registra como
> fallida (`synthesis_total{status="skipped"|"failed"}`) y la corrida continúa
> con normalidad — los informes simplemente no llevan finding. Apunte
> `LLM_BASE_URL` a su propio Ollama, o configure `LLM_PROVIDER=anthropic|openai`
> con su clave de API.

### 3. Verificar

```bash
# Salud del Orchestrator
curl http://localhost:8000/health

# OpenCTI (puede tardar 2–3 min en arrancar completamente)
curl http://localhost:8080/health

# Abrir la consola mínima de operación (la página pide la API key si la auth está activa)
xdg-open http://localhost:8000/console
```

#### Flujo seguro de API key en consola

- Modo por defecto de sesión: la clave queda solo en memoria JS y se limpia del input al pulsar **Usar clave**.
- **Recordar en este navegador** es opt-in explícito y guarda la clave en `sessionStorage` (se borra al cerrar la pestaña).
- El shell de la consola (`/console`, `/console/i18n.json`) es público porque no contiene datos; cada petición que hace lleva la clave y se rechaza sin ella. Véase [ADR-006 — Modelo de acceso desde navegador](docs/adr/ADR-006-oidc-proxy-es.md#modelo-de-acceso-desde-navegador).
- La consola nunca pone la clave en URLs y muestra guía accionable ante error 401 por clave inválida/rotada.

### 4. Primera ejecución

```bash
export KEY="$(grep '^ORCHESTRATOR_API_KEY=' .env | cut -d= -f2)"

# Lanzar una recolección — responde 202 de inmediato, la corrida sigue en segundo plano
curl -X POST -H "X-API-Key: $KEY" \
  http://localhost:8000/targets/example-domain/run
# {"run_id": 1, "status": "accepted", "target_id": "example-domain"}

# Consultar hasta que el estado deje de ser pending/running
curl -H "X-API-Key: $KEY" http://localhost:8000/runs/1

# Qué hay de nuevo respecto de la ejecución anterior de ese objetivo
curl -H "X-API-Key: $KEY" http://localhost:8000/runs/1/delta

# El informe para el operador (Markdown, también en disco bajo daily_reports/)
curl -H "X-API-Key: $KEY" http://localhost:8000/runs/1/report
```

### 5. Opcional: perfil MISP

```bash
docker compose -f docker-compose.yml -f docker-compose.misp.yml --profile misp up -d
```

> ⚠ **MISP tarda 5–10 minutos en inicializarse la primera vez.** Espere a que
> el contenedor `misp` reporte healthy antes de arrancar `connector-misp`.

Véase [MISP](#misp) más abajo para el orden de arranque y la configuración.

### Puerta de entrada autenticada opcional (perfil auth)

Si desea un flujo de inicio de sesión estándar de producción, arranque la capa
OIDC opcional sobre el stack base:

```bash
docker compose -f docker-compose.yml -f docker-compose.auth.yml --profile auth up -d
curl http://localhost:8002/health
```

Esto añade Keycloak en `http://localhost:8085` y un proxy oauth2 en
`http://localhost:8002` (`AUTH_PROXY_PORT`; 8002 es también el valor que trae
`.env.example`; no use 8001, que colisiona con el servicio `socialosint`).
`auth-proxy` espera a que Keycloak y el orquestador estén healthy antes de
arrancar.

**Crear una cuenta de operador** (no se distribuyen credenciales demo — véase
[ADR-006](docs/adr/ADR-006-oidc-proxy-es.md)):

1. Abra `http://localhost:8085` y entre con `KEYCLOAK_ADMIN` /
   `KEYCLOAK_ADMIN_PASSWORD` de su archivo `.env`.
2. Seleccione el realm **orchestrator** → **Users** → **Add user**.
3. Rellene nombre de usuario / correo, configure la contraseña en
   **Credentials** y márcela como permanente.

El orchestrator base sigue escuchando en la red compose en
`http://orchestrator:8000`. La capa de auth expone la puerta en
`http://localhost:8002`; el puerto 8000 del stack base sigue publicado en
loopback para acceso directo desde el host.

> **Nota de arquitectura:** el proxy OIDC es una capa de perímetro *opcional* —
> no reemplaza el mecanismo `X-API-Key` (ADR-005). Los clientes que ya envían
> una clave de API siguen funcionando sin cambios. Véase
> [ADR-006](docs/adr/ADR-006-oidc-proxy-es.md).

---

## MISP

MISP corre desde el overlay opcional `docker-compose.misp.yml` (`--profile misp`) con su propia
**MariaDB** y su propio **Redis** (no comparte la infraestructura de OpenCTI).
La sincronización OpenCTI ↔ MISP la hace el conector oficial
[`opencti/connector-misp`](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/misp)
(versión **6.8.11**, fijada para coincidir con la plataforma).

### Orden de arranque

```bash
# 1. Arrancar el stack MISP y esperar la inicialización (5–10 min la primera vez)
docker compose -f docker-compose.yml -f docker-compose.misp.yml --profile misp up -d misp-db misp-redis misp-modules misp
docker compose -f docker-compose.yml -f docker-compose.misp.yml --profile misp logs -f misp   # esperar hasta "MISP is ready"

# 2. Con MISP healthy, arrancar el conector de OpenCTI
docker compose -f docker-compose.yml -f docker-compose.misp.yml --profile misp up -d connector-misp
```

### Obtener la clave de API de MISP

1. Abra `https://localhost:8443` en el navegador (acepte el certificado autofirmado).
2. Inicie sesión con `MISP_ADMIN_EMAIL` / `MISP_ADMIN_PASSWORD` del `.env`.
3. Vaya a **Administration → List Auth Keys → Add Authentication Key**.
4. Copie la clave hexadecimal de 40 caracteres en `MISP_KEY` del `.env`.
5. Reinicie el conector: `docker compose -f docker-compose.yml -f docker-compose.misp.yml --profile misp restart connector-misp`.

### Verificar el registro del conector

En OpenCTI, vaya a **Data → Connectors**. El conector llamado **MISP** debería
aparecer con estado "Connected" al minuto de arrancar. Si figura desconectado,
revise `docker compose logs connector-misp` en busca de errores de autenticación.

### Requisitos de hardware (adicionales)

| Componente adicional | RAM |
| --- | --- |
| MariaDB (MISP) | ~256 MB |
| Redis (MISP) | ~128 MB |
| Núcleo de MISP (PHP-FPM + nginx) | ~1 GB |
| `connector-misp` | ~256 MB |
| **Total adicional** | **~1,6 GB** |

---

## SocialOSINT

El recolector SocialOSINT integra el
[OWASP SocialOSINT Agent](https://github.com/bm-github/owasp-social-osint-agent)
(MIT) para el análisis, asistido por LLM, de cuentas de redes sociales
asociadas a un objetivo. Diseño y justificación de la integración:
[`docs/socialosint.md`](docs/socialosint.md).

**Este recolector está deshabilitado por defecto**
(`collectors.socialosint.enabled: false`). Hay que habilitarlo explícitamente
por objetivo en `targets.yaml`.

### Plataformas

| Plataforma | Credenciales necesarias | Notas |
| --- | --- | --- |
| Twitter/X | `SOCIALOSINT_TWITTER_BEARER_TOKEN` | bearer token v2 |
| Reddit | `SOCIALOSINT_REDDIT_CLIENT_ID`, `SOCIALOSINT_REDDIT_CLIENT_SECRET` | credenciales PRAW |
| GitHub | `SOCIALOSINT_GITHUB_TOKEN` | opcional (menor límite de tasa sin él) |
| Bluesky | `SOCIALOSINT_BLUESKY_IDENTIFIER`, `SOCIALOSINT_BLUESKY_APP_SECRET` | app password (formato `<xxxx-xxxx-xxxx-xxxx>`) |
| Mastodon | `SOCIALOSINT_MASTODON_INSTANCE_1_URL`, `SOCIALOSINT_MASTODON_INSTANCE_1_TOKEN` | una entrada por instancia |
| HackerNews | *(ninguna)* | API pública de Algolia |

Una plataforma sin credenciales se omite en silencio con una advertencia: **no**
hace fallar al recolector.

### Requisitos de LLM

SocialOSINT necesita su propio LLM (compatible con OpenAI, con soporte de
visión). Defina `SOCIALOSINT_LLM_BASE_URL`, `SOCIALOSINT_LLM_API_KEY`,
`SOCIALOSINT_LLM_MODEL` y `SOCIALOSINT_LLM_VISION_MODEL` en `.env`. Son
independientes del `LLM_PROVIDER` del orquestador.

### Uso

```bash
# Construir y arrancar el servicio SocialOSINT
docker compose --profile socialosint up -d socialosint

# Habilitarlo para un objetivo concreto en targets.yaml:
# collectors:
#   socialosint:
#     enabled: true
#     usernames: [brandhandle]
#     platforms: [twitter, github, hackernews]
```

### APIs y uso de los datos

El recolector usa las **APIs oficiales** de cada plataforma (no hace scraping).
Aun así, el uso de los datos recolectados está sujeto a los términos de
desarrollador de cada plataforma:

> ⚠️ **X/Twitter** en particular restringe almacenar y redistribuir datos de
> usuarios bajo su acuerdo de desarrollador. Asegúrese de que su caso de uso
> cumple antes de habilitar la recolección de Twitter. Por eso el recolector es
> **opt-in**.

El informe de análisis del LLM se guarda como una Note en OpenCTI etiquetada
*"análisis de SocialOSINT, no verificado"* y no se trata como hecho verificado.
El timeout configurado es un límite total de tiempo de pared para el flujo
completo, no un límite por petición. Una vez creada una sesión en SocialOSINT,
el orquestador intenta eliminarla al terminar correctamente, fallar o agotar el
tiempo.

---

## Amass

El recolector Amass integra [OWASP Amass v5](https://github.com/owasp-amass/amass)
(Apache-2.0) para la enumeración en profundidad de subdominios del dominio raíz
del objetivo: transparencia de certificados, DNS pasivo, decenas de fuentes
públicas y fuerza bruta opcional, con cada nombre resuelto a sus direcciones.
Complementa a SpiderFoot (amplio, guiado por módulos) con el mapa de superficie
de ataque más profundo que ofrece el ecosistema de código abierto.

**Este recolector está deshabilitado por defecto**
(`collectors.amass.enabled: false`). Hay que habilitarlo explícitamente por
objetivo en `targets.yaml`.

### Cómo se ejecuta

Amass v5 se divide en un **engine** de larga duración y clientes CLI ligeros. El
engine corre como el servicio compose `amass` (imagen oficial, perfil `amass`);
la imagen del orquestador incluye los clientes `oam_enum` y `oam_subs`. En cada
ejecución el recolector:

1. comprueba `GET /api/v1/health` en `AMASS_ENGINE_URL`;
2. ejecuta `oam_enum -engine … -d <fqdn>`: el engine enumera hasta que pasan
   `progress_timeout_minutes` sin hallazgos nuevos;
3. ejecuta `oam_subs -d <fqdn> -names -ip` sobre la base de datos de activos del
   volumen compartido con el engine (`AMASS_DATA_DIR`) y traduce cada línea a
   STIX: un `domain-name` por nombre descubierto, `ipv4-addr` / `ipv6-addr` por
   dirección, `resolves-to` (nombre → dirección) y `related-to` (nombre → raíz
   del objetivo).

Engine caído, binarios ausentes, salida distinta de cero o el límite de tiempo de
pared `timeout_seconds` devuelven `success=False`, de modo que la ejecución se
registra como parcial o fallida en vez de informar cero hallazgos.

### Fuentes de datos y credenciales

Las claves de API de las fuentes de datos nunca llegan al orquestador: viven en
`amass/datasources.yaml`, ignorado por git y montado sólo en el contenedor del
engine. Parta del ejemplo (el engine arranca sin claves — las fuentes públicas
se usan sin ellas):

```bash
cp amass/datasources.example.yaml amass/datasources.yaml   # obligatorio: el fichero se monta con bind
docker compose --profile amass up -d amass
```

`amass/config.yaml` (con el alcance vacío a propósito — el recolector pasa el
dominio de cada objetivo) se monta de la misma forma.

### Uso

```bash
# Habilitarlo para un objetivo concreto en targets.yaml:
# collectors:
#   amass:
#     enabled: true
#     active: false                  # transferencias de zona y certificados tocan el objetivo
#     brute: false
#     progress_timeout_minutes: 10
#     timeout_seconds: 1800
```

> ⚠️ **Modo activo** (`active: true`) intenta transferencias de zona y lectura
> de nombres en certificados TLS contra los propios servidores del objetivo, y
> la fuerza bruta genera grandes volúmenes de consultas DNS. Mantenga ambos
> desactivados salvo que la `authorization` del objetivo cubra explícitamente
> sondeos activos.

---

## Tavily

El recolector Tavily realiza diligencia web pública sobre una entidad
autorizada. Es opt-in por diseño y se mantiene apagado hasta que un objetivo
habilita `collectors.tavily.enabled: true`.

**Este recolector está deshabilitado por defecto** (`collectors.tavily.enabled: false`).

### Qué busca

- noticias adversas y cobertura pública
- sanciones, acciones regulatorias y litigios
- estructura societaria y accionistas publicados
- beneficiarios finales y relaciones jurídicas
- URLs origen y fragmentos resumidos de resultados públicos

Cada consulta busca un término exacto entrecomillado en fuentes de terceros
(prensa, registros, expedientes judiciales); por defecto ese término es el
nombre de dominio del objetivo. Podés sobreescribirlo por objetivo con
`search_terms` (para nombres de entidad, marcas o alias). Nunca acota la
búsqueda al dominio del propio objetivo, porque la prensa adversa se publica en
otros sitios. Usá `include_domains` / `exclude_domains` para restringir las
fuentes. Una página devuelta por varias consultas, en cualquier variante de
esquema, mayúsculas o barra final, produce un único observable `url` y una
única nota. Una consulta que falla tras sus reintentos queda registrada en una
nota; la ejecución falla sólo cuando fallaron todas las consultas. Con varios
términos, el orden de consultas alterna por término dentro de cada plantilla,
así un presupuesto de llamadas más bajo igual alcanza todos los términos con
la(s) primera(s) plantilla(s).

### Uso

```yaml
collectors:
  tavily:
    enabled: true
    search_depth: basic
    max_results: 5
    include_domains: []
    exclude_domains: []
    max_calls_per_run: 3
    timeout_seconds: 120
```

| Campo | Por defecto | Significado |
| --- | --- | --- |
| `enabled` | `false` | Interruptor opt-in; el recolector solo se registra en una ejecución cuando vale `true` |
| `search_depth` | `basic` | `basic` o `advanced` (el precio de Tavily difiere) |
| `max_results` | `5` | Resultados pedidos y conservados por consulta, 1–20, recortado por `TAVILY_MAX_RESULTS` |
| `include_domains` / `exclude_domains` | `[]` | Lista blanca / negra de dominios de resultados; vacío usa los valores globales |
| `search_terms` | `[]` | Lista opcional de términos de consulta entrecomillados (por ejemplo nombres comerciales), hasta 5 entradas de como máximo 80 caracteres cada una; vacío mantiene el dominio como término por defecto |
| `include_answer` | `false` | Pide además la respuesta sintetizada de Tavily, conservada como una nota acotada por consulta |
| `max_calls_per_run` | `3` | Peticiones de búsqueda por ejecución, 1–20, recortado por `TAVILY_MAX_CALLS_PER_RUN`; se incluyen tres plantillas de consulta, así que el valor por defecto las cubre todas |
| `timeout_seconds` | `TAVILY_TIMEOUT_SECONDS` (`120`) | Presupuesto de tiempo de pared de toda la ejecución del recolector, reintentos y esperas incluidos |

Las peticiones se reintentan con espera exponencial solo ante HTTP 429, 5xx y
errores de transporte; cualquier otro 4xx (clave inválida, payload rechazado)
hace fallar la consulta de inmediato. Las URLs de los resultados se conservan
solo con esquema `http` o `https`.

---

## Configuración

Todas las variables están listadas con un comentario en
[`.env.example`](.env.example); copie ese archivo a `.env` y edítelo.
[`orchestrator/config.py`](orchestrator/config.py) es la definición
autoritativa — lo que no esté declarado ahí es ignorado por la aplicación.

En el mismo `.env` conviven dos grupos de variables:

- **Configuración de la aplicación** (`ORCHESTRATOR_*`, `LLM_*`, `ALERT_*`,
  `SPIDERFOOT_URL`, `SOCIALOSINT_URL`, …) — declarada en `config.py` y leída por
  el proceso del orquestador. Sus valores por defecto apuntan a una ejecución
  bare-metal (URLs `localhost`, `./orchestrator.db`).
- **Configuración exclusiva de compose** (`OPENCTI_ADMIN_*`, `MINIO_*`,
  `RABBITMQ_*`, `MISP_*`, `KEYCLOAK_*`, `AUTH_*`, `OIDC_*`, `SOCIALOSINT_LLM_*`
  y las credenciales de plataformas de SocialOSINT, …) — consumida por
  `docker-compose*.yml` para configurar los demás servicios. `.env.example`
  trae los valores de la red de contenedores (`http://opencti:8080`,
  `/app/data/…`), que sobrescriben los defaults bare-metal al correr bajo Docker.

**Antes de que esto salga de una laptop:**

| Variable | Por defecto | Por qué importa |
| --- | --- | --- |
| `ORCHESTRATOR_API_KEY` | *(vacío)* | Vacío significa que **la API está abierta**. Véase [Autenticación](#autenticación-de-la-api-fase-5). |
| `OPENCTI_ADMIN_TOKEN` | *(vacío)* | Debe coincidir con el token con el que se inicializó OpenCTI, o la ingesta falla. |
| `OPENCTI_ADMIN_PASSWORD` | `ChangeMe!` | Marcador de posición — es el login web de OpenCTI. |
| `MINIO_ROOT_PASSWORD` | `ChangeMinio!` | Marcador de posición. |
| `RABBITMQ_DEFAULT_PASS` | `guest` | Marcador de posición. |
| `ORCHESTRATOR_SECRET_KEY` | `insecure-dev-key` | Marcador de posición. |
| `ALERT_WEBHOOK_SECRET` | *(vacío)* | Sin él los payloads de webhook van sin firmar. |

**Las que se ajustan habitualmente:**

| Variable | Por defecto | Significado |
| --- | --- | --- |
| `ORCHESTRATOR_LANGUAGE` | `es` | Idioma orientado al operador, `es` o `en` ([ADR-004](docs/adr/ADR-004-language-policy-es.md)). |
| `ORCHESTRATOR_LOG_LEVEL` | `INFO` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR`. |
| `ORCHESTRATOR_LOG_FORMAT` | `text` | `text` para una terminal, `json` para un recolector de logs. |
| `ORCHESTRATOR_METRICS_ENABLED` | `true` | `false` hace que `GET /metrics` devuelva 404. |
| `ORCHESTRATOR_ENV_FILE` | `.env` | Ruta bootstrap del dotenv usada al construir `Settings()`. Déjela vacía para desactivar la carga de dotenv (los tests hacen esto para no leer el `.env` local del desarrollador). |
| `ORCHESTRATOR_DATABASE_URL` | `sqlite+aiosqlite:////app/data/orchestrator.db` | Dentro del contenedor esa ruta es el volumen persistente; fuera de Docker use `./orchestrator.db`. |
| `TARGETS_FILE` | `targets.yaml` | Se relee en cada llamada de la API y del scheduler. |
| `OPENCTI_SSL_VERIFY` | `true` | Use `false` solo en dev con TLS local/autofirmado. |
| `SPIDERFOOT_MODULES` | `sfp_dnsresolve,sfp_whois,sfp_sslcert` | Valor de respaldo cuando un objetivo no lista módulos. |
| `SPIDERFOOT_URL` | `http://spiderfoot:5001` | URL del servicio SpiderFoot en la red interna. |
| `SPIDERFOOT_TIMEOUT_SECONDS` | `600` | Tiempo máximo de una recolección de SpiderFoot. |
| `LLM_PROVIDER` / `LLM_MODEL` / `LLM_BASE_URL` | `ollama` / `llama3.2` / `http://ollama:11434` | Backend de síntesis; `ollama` mantiene los datos on-prem. `none` desactiva la síntesis para todos los objetivos. `nebius` usa el endpoint compatible con OpenAI de Token Factory. |
| `LLM_MODEL_REASONING` | *(vacío)* | Override opcional del modelo para síntesis y llamadas de razonamiento intensivo de relaciones en los proveedores cloud (`anthropic`, `openai`, `nebius`); si está vacío usa `LLM_MODEL`. Ollama siempre usa `OLLAMA_MODEL`. |
| `LLM_MODEL_FAST` | *(vacío)* | Override opcional del modelo para llamadas rápidas de clasificación/extracción en los proveedores cloud; si está vacío usa `LLM_MODEL`. |
| `OLLAMA_MODEL` | `llama3.2` | Modelo servido por Ollama para targets con `llm: local`. |
| `LLM_TIMEOUT_SECONDS` | `120` | Tiempo máximo de una solicitud de síntesis. |
| `LLM_MAX_TOKENS` | `2048` | Límite superior de la respuesta del modelo. |
| `LLM_MAX_OBSERVABLES_IN_PROMPT` | `200` | Límite de observables enviados al prompt del sintetizador. |
| `SYNTHESIS_HISTORY_RUNS` | `5` | Cantidad de ejecuciones previas usadas como contexto. |
| `SYNTHESIS_OPENCTI_CONTEXT` | `false` | Si es `true`, enriquece la síntesis con contexto de OpenCTI. |
| `OPENAI_API_KEY` | *(vacío)* | Requerida cuando `LLM_PROVIDER=openai`. |
| `OPENAI_BASE_URL` | *(vacío)* | URL base opcional para endpoints compatibles con OpenAI. |
| `NEBIUS_API_KEY` | *(vacío)* | Requerida cuando `LLM_PROVIDER=nebius`. |
| `NEBIUS_BASE_URL` | `https://api.tokenfactory.nebius.com/v1` | URL base compatible con OpenAI de Nebius Token Factory. |
| `ANTHROPIC_API_KEY` | *(vacío)* | Requerida cuando `LLM_PROVIDER=anthropic`. |
| `OPENCTI_INGEST_RETRIES` / `OPENCTI_INGEST_BACKOFF_SECONDS` | `3` / `2.0` | Reintentos tras un error *transitorio* de OpenCTI, y la espera base (se duplica en cada reintento, ±25 % de jitter, tope 30 s). Un token inválido nunca se reintenta. |
| `OPENCTI_OUTBOX_CRON` | `*/5 * * * *` | Cron UTC para reintentos del outbox de OpenCTI. |
| `OPENCTI_OUTBOX_MAX_ATTEMPTS` | `6` | Intentos totales del outbox de OpenCTI (incluye el primero). |
| `OPENCTI_OUTBOX_BASE_DELAY_SECONDS` | `60.0` | Espera base del backoff exponencial del outbox. |
| `OPENCTI_OUTBOX_JITTER_RATIO` | `0.25` | Ratio de jitter aplicado a los reintentos del outbox. |
| `SOCIALOSINT_URL` | `http://socialosint:8000` | URL del servicio SocialOSINT. |
| `SOCIALOSINT_TIMEOUT_SECONDS` | `300` | Límite total de tiempo de pared para una ejecución completa de SocialOSINT. |
| `AMASS_ENGINE_URL` | `http://amass:4000` | URL del engine de Amass (perfil compose `amass`). |
| `AMASS_DATA_DIR` | `/app/amass/data` | Volumen compartido con el engine; `asset.db` se lee desde aquí. |
| `AMASS_ENUM_BIN` / `AMASS_SUBS_BIN` | `oam_enum` / `oam_subs` | Clientes CLI de Amass (rutas absolutas fuera de Docker). |
| `AMASS_TIMEOUT_SECONDS` | `1800` | Límite de tiempo de pared por defecto de una ejecución completa de Amass (enum + subs). |
| `TAVILY_API_KEY` | *(vacío)* | Requerida cuando `collectors.tavily.enabled=true`; dejarla vacía mantiene el recolector apagado. |
| `TAVILY_SEARCH_DEPTH` | `basic` | Profundidad de la búsqueda Tavily: `basic` o `advanced`. |
| `TAVILY_MAX_RESULTS` | `5` | Techo global de resultados por consulta, 1–20; el `max_results` por objetivo se recorta a este valor. |
| `TAVILY_TIMEOUT_SECONDS` | `120` | Presupuesto de tiempo de pared por defecto de toda la ejecución de Tavily por objetivo, reintentos incluidos (`timeout_seconds` en `targets.yaml` lo sobreescribe). |
| `TAVILY_MAX_CALLS_PER_RUN` | `3` | Techo global de peticiones de búsqueda por ejecución, 0–20; el `max_calls_per_run` por objetivo se recorta a este valor y `0` apaga el recolector para todos los objetivos (se omite, no falla). |
| `TAVILY_INCLUDE_DOMAINS` | *(vacío)* | Lista opcional de dominios permitidos en los resultados, separados por coma (`example.com,news.example.com`). |
| `TAVILY_EXCLUDE_DOMAINS` | *(vacío)* | Lista opcional de dominios a excluir de los resultados, separados por coma. |
| `ALERT_TIMEOUT_SECONDS` | `10` | Tiempo máximo por intento de envío de alerta (webhook/email). |
| `ALERT_SMTP_PORT` | `587` | Puerto SMTP para alertas por correo. |
| `ALERT_SMTP_USER` | *(vacío)* | Usuario SMTP para alertas por correo. |
| `ALERT_SMTP_PASSWORD` | *(vacío)* | Contraseña SMTP para alertas por correo. |
| `ALERT_SMTP_FROM` | *(vacío)* | Remitente para alertas por correo. |
| `ALERT_SMTP_STARTTLS` | `true` | Activa STARTTLS para conexiones SMTP. |
| `SHODAN_API_KEY` | *(vacío)* | Clave opcional que se pasa a módulos de enriquecimiento OpenOSINT. |
| `VIRUSTOTAL_API_KEY` | *(vacío)* | Clave opcional que se pasa a módulos de enriquecimiento OpenOSINT. |
| `CENSYS_API_ID` | *(vacío)* | Clave opcional que se pasa a módulos de enriquecimiento OpenOSINT. |
| `CENSYS_API_SECRET` | *(vacío)* | Clave opcional que se pasa a módulos de enriquecimiento OpenOSINT. |

Las claves opcionales de enriquecimiento (`SHODAN_API_KEY`,
`VIRUSTOTAL_API_KEY`, `CENSYS_API_ID`, `CENSYS_API_SECRET`) se pasan a
OpenOSINT y pueden quedar sin definir.

---

## API

La API del orquestador se publica en el puerto **8000** del host
(`http://localhost:8000`, o `http://orchestrator:8000` en la red de Docker). Con
la [puerta de entrada autenticada](#puerta-de-entrada-autenticada-opcional-perfil-auth)
opcional activa, use `http://localhost:${AUTH_PROXY_PORT:-8002}` desde el
navegador. Las rutas públicas son `GET /`, `GET /docs`, `GET /docs/*`,
`GET /openapi.json`, `GET /redoc`, `GET /health`, `GET /metrics`, `GET /console`
y `GET /console/i18n.json`. Todo lo demás exige una clave de API; véanse
[Autenticación](#autenticación-de-la-api-fase-5) y
[ADR-006](docs/adr/ADR-006-oidc-proxy-es.md).

| Método | Ruta | Descripción |
| --- | --- | --- |
| `GET` | `/` | Página de bienvenida con enlaces a consola, docs y health (sin clave de API) |
| `GET` | `/health` | Comprobación de disponibilidad (sin clave de API) |
| `GET` | `/metrics` | Métricas Prometheus (sin clave de API) |
| `GET` | `/console/i18n.json` | Catálogo de traducciones de la consola (público; sin datos de targets/runs) |
| `GET` | `/console` | Shell de la consola de operación (público, sin datos; cada llamada que hace exige la API key, que se introduce en la página) |
| `GET` | `/analytics/risk-trends` | Tendencias por target de riesgo y nuevos observables para la vista de riesgo |
| `GET` | `/targets` | Listar objetivos configurados |
| `GET` | `/targets/{id}` | Obtener un objetivo concreto |
| `POST` | `/targets/{id}/run` | Lanzar una recolección — `202`, devuelve `run_id`, corre en segundo plano |
| `POST` | `/scheduler/reload/preview` | Previsualizar cambios de cron desde `targets.yaml` sin mutar jobs |
| `POST` | `/scheduler/reload` | Recargar los jobs cron desde `targets.yaml` sin reiniciar el proceso |
| `POST` | `/alerts/dlq/replay` | Reintentar alertas en cola DLQ (`channel` = `webhook` \| `email`, `limit` = `1..1000`) |
| `POST` | `/opencti/outbox/replay` | Reintentar bundles OpenCTI en DLQ (`run_id`, `limit` = `1..1000`) y drenar ahora los vencidos |
| `GET` | `/runs` | Las 100 ejecuciones más recientes, de más nueva a más vieja; `?target_id=` filtra |
| `GET` | `/runs/{id}` | Estado, conteos y auditoría `alerts[]` de una ejecución |
| `GET` | `/runs/{id}/delta` | Observables nuevos de esa ejecución (desde la base, no desde archivos) |
| `GET` | `/runs/{id}/report` | Reporte Markdown de una ejecución completada (`text/plain`) |
| `GET` | `/runs/{id}/finding` | Finding sintetizado por el LLM de una ejecución completada |

`GET /runs/{id}/finding` devuelve `new_since_last_run` y
`suggested_pivots` como arreglos JSON de cadenas (no como cadenas con JSON).

La documentación interactiva está en `/docs` (OpenAPI en `/openapi.json`).

**Estados de una ejecución** — `pending` → `running` → uno de:

| Estado | Significado |
| --- | --- |
| `success` | Todos los recolectores habilitados terminaron bien |
| `partial` | Al menos un recolector terminó bien y algo falló — un recolector, o la ingesta en OpenCTI de un bundle |
| `failed` | Todos fallaron |

Un fallo de ingesta en OpenCTI también cuenta como error: la corrida termina
`partial` con `opencti-sink: …` en su campo `error`, el fallo se cuenta en
`osint_orchestrator_opencti_ingest_total{outcome="failure"}`, y los observables
cuyo bundle no llegó quedan sin ingestar y se vuelven a reportar como nuevos en
la corrida siguiente. Los bundles fallidos se persisten en `opencti_outbox` y
se reintentan en segundo plano con el worker `opencti-outbox` — una
transacción por bundle, así que una caída a mitad del drenado nunca reenvía lo
que ya llegó. Sólo se reintentan los fallos *transitorios*; uno permanente
(token inválido, bundle rechazado) pasa directamente a `dead_letter`, se
registra en `WARNING` y se cuenta en `opencti_outbox_dead_letter`: corrija la
causa y luego `POST /opencti/outbox/replay`. Cuando un bundle diferido por fin
llega, sus observables se marcan como ingestados y se registran como vistos,
de modo que las corridas siguientes y `GET /runs/{id}/delta` los reportan
correctamente; la fila conserva su rastro de auditoría pero descarta el
STIX (ADR-003).

**Las respuestas de error** llevan un `detail` localizado según
[ADR-004](docs/adr/ADR-004-language-policy-es.md): `404` para un objetivo,
ejecución, reporte o finding inexistente; `400` para un objetivo que existe
pero está `enabled: false`; `401` para clave de API ausente o incorrecta; `409`
cuando el objetivo ya tiene una ejecución activa.

---

## Configuración de objetivos

Edite `targets.yaml` ([`targets.example.yaml`](targets.example.yaml) es un
punto de partida comentado). **`authorization` y `purpose` son obligatorios**
— se registran con cada ejecución para la pista de auditoría.

```yaml
targets:
  - id: mi-dominio
    enabled: true
    fqdn: ejemplo.com
    authorization: "Propiedad propia. Autorizado por: Fulano de Tal el 2026-09-01"
    purpose: "Monitorización continua de exposición"
    collectors:
      openosint:
        enabled: true
        investigation_type: domain
      spiderfoot:
        enabled: true
        modules: []       # vacío = usar SPIDERFOOT_MODULES de .env
    schedule:
      cron: "0 8 * * *"  # diariamente a las 08:00 UTC
    llm: local            # mantiene los datos on-prem (Ollama)
```

### Referencia de campos

| Clave | Por defecto | Significado |
| --- | --- | --- |
| `id` | *obligatorio* | Identificador estable; se usa en rutas, etiquetas de métricas y directorios de informes |
| `fqdn` | *obligatorio* | La entidad semilla que reciben los recolectores |
| `authorization` | *obligatorio* | Quién aprobó este objetivo y cuándo |
| `purpose` | *obligatorio* | Por qué se monitoriza |
| `enabled` | `true` | `false` omite el job cron; una ejecución manual devuelve `400` |
| `llm` | `local` | `local` \| `anthropic` \| `openai` \| `nebius` — anula `LLM_PROVIDER` |
| `language` | *(heredado)* | `es` \| `en` — anula `ORCHESTRATOR_LANGUAGE` |
| `report_dir` | `daily_reports` | Directorio raíz de los artefactos de este objetivo |

`collectors.openosint`:

| Clave | Por defecto | Significado |
| --- | --- | --- |
| `enabled` | `true` | |
| `investigation_type` | `domain` | `auto` \| `domain` \| `email` \| `username` \| `ip` \| `phone` \| `url` \| `hash` \| `person` |
| `max_depth` | `2` | Saltos de BFS desde la entidad semilla |
| `max_entities` | `40` | Entidades distintas desde las que pivotar |
| `max_tool_calls` | `60` | Invocaciones de herramienta en toda la ejecución |
| `tool_timeout_seconds` | `30` | Tope por llamada a herramienta |

Las cuatro claves de presupuesto son cotas duras de la búsqueda por pivoteo.
Sin ellas una ejecución programada puede expandirse sin límite.

`collectors.spiderfoot`:

| Clave | Por defecto | Significado |
| --- | --- | --- |
| `enabled` | `true` | |
| `modules` | `[]` | Nombres de módulos de SpiderFoot (`sfp_*`); vacío recurre a `SPIDERFOOT_MODULES` |
| `timeout_seconds` | `600` | Cuánto esperar a que termine el escaneo completo |

`collectors.socialosint`:

| Clave | Por defecto | Significado |
| --- | --- | --- |
| `enabled` | `false` | Opt-in (Fase 4b); requiere el servicio compose `socialosint` |
| `usernames` | `[]` | Handles a investigar; lista vacía ⇒ se omite el recolector |
| `platforms` | `[twitter, reddit, github, bluesky, hackernews]` | Los valores válidos añaden `mastodon`; las plataformas sin credenciales en `.env` se omiten con una advertencia |
| `timeout_seconds` | `SOCIALOSINT_TIMEOUT_SECONDS` (`300`) | Límite total de tiempo de pared del flujo completo; las sesiones creadas en el servicio se eliminan de forma best-effort al salir |

`collectors.amass`:

| Clave | Por defecto | Significado |
| --- | --- | --- |
| `enabled` | `false` | Opt-in; requiere el servicio compose `amass` (véase [Amass](#amass)) |
| `active` | `false` | Transferencias de zona y lectura de certificados contra el objetivo (`oam_enum -active`) |
| `brute` | `false` | Fuerza bruta con diccionario tras las búsquedas pasivas (`oam_enum -brute`) |
| `include` / `exclude` | `[]` | Nombres de fuentes de datos a las que restringir la ejecución / a excluir |
| `progress_timeout_minutes` | `10` | Minutos sin hallazgos nuevos antes de detener la enumeración |
| `timeout_seconds` | `AMASS_TIMEOUT_SECONDS` (`1800`) | Límite duro de tiempo de pared de todo el recolector (enum + subs); el proceso CLI se mata al vencer |

`schedule`:

| Clave | Por defecto | Significado |
| --- | --- | --- |
| `cron` | `"0 8 * * *"` | Expresión [APScheduler](https://apscheduler.readthedocs.io) de cinco campos, en UTC |
| `misfire_grace_time_seconds` | `3600` | Omitir una ejecución perdida por más de este margen en vez de lanzarla con retraso |

`alerts`: véase [Alertas](#alertas-fase-4a).

El archivo se relee en cada llamada de la API y del scheduler, así que los
cambios en un objetivo aplican en la siguiente corrida. Los cron quedan
cargados como jobs de APScheduler; cuando cambie `schedule.cron` o `enabled`,
aplique el cambio al momento con:

```bash
curl -X POST -H "X-API-Key: $KEY" http://localhost:8000/scheduler/reload/preview
curl -X POST -H "X-API-Key: $KEY" http://localhost:8000/scheduler/reload
```

---

## Idioma

La salida orientada al operador — informes diarios, síntesis LLM, detalles de errores de la API — se genera en español por defecto. El código fuente, los logs, los commits y la documentación técnica están en inglés. La regla y su justificación se encuentran en [ADR-004](docs/adr/ADR-004-language-policy.md) ([versión en español](docs/adr/ADR-004-language-policy-es.md)).

```bash
ORCHESTRATOR_LANGUAGE=es    # es | en — idioma global por defecto
```

Override por objetivo en `targets.yaml`, para cuando los informes de un objetivo van a un lector diferente:

```yaml
targets:
  - id: mi-dominio
    language: en      # omitir para heredar ORCHESTRATOR_LANGUAGE
```

Un valor no reconocido se registra y se ignora en lugar de lanzar una excepción, de modo que un error tipográfico degrada el idioma del informe en lugar de detener la recolección. Los identificadores que se comparan o persisten — `risk_level`, `RunStatus`, tipos STIX — permanecen en inglés independientemente del idioma configurado.

---

## Reportes (Fase 2)

Cada corrida escribe artefactos en `daily_reports/YYYY-MM-DD/<target_id>/` (fecha UTC):

- `report.md` — reporte para operador con trazabilidad, estado por collector, sección delta primero, inventario completo, relaciones, errores y marcador de síntesis de Fase 3.
- `bundle.stix.json` — bundle STIX combinado y determinista de la corrida.
- `delta.json` — sólo observables marcados como nuevos respecto de la corrida previa.
- `report.pdf` — render best-effort con `fpdf2` (opcional; si falta la librería o falla, la corrida sigue y los otros archivos se generan igual).

Además el orquestador regenera `daily_reports/YYYY-MM-DD/index.md` al finalizar cada corrida como resumen ejecutivo diario (una fila por objetivo).

---

## Alertas (Fase 4a)

Después de cada corrida el orquestador evalúa reglas de envío y notifica por
los canales configurados. Los intentos se registran en `alerts`; las fallas se
persisten en `alert_deliveries` para reintentos con backoff y manejo de DLQ.

### Canales

| Canal | Variables necesarias |
| --- | --- |
| **Webhook** | `ALERT_WEBHOOK_URL` (+ `ALERT_WEBHOOK_SECRET` para firmar) |
| **Email (SMTP)** | `ALERT_SMTP_HOST`, `ALERT_EMAIL_TO` (+ variables opcionales de auth/TLS) |

Un canal sin sus variables se omite y se registra una advertencia **una sola
vez** al arrancar.

### Cola de reintentos y DLQ

La cola es el único bucle de reintentos: un notificador hace exactamente un
intento por llamada, así que `ALERT_RETRY_MAX_ATTEMPTS` es el número real de
llamadas de red. Cada entrega se reclama y confirma antes del envío y se
cierra justo después, por lo que una caída o dos drenados concurrentes cuestan
como mucho un duplicado. Un fallo que el receptor va a repetir — un `4xx`
distinto de `429`, un rechazo SMTP de autenticación o de destinatario, un
canal sin configurar — se salta los reintentos y pasa a `dead_letter` de
inmediato; los timeouts, `5xx` y `429` se reintentan con backoff exponencial.

| Variable | Por defecto | Descripción |
| --- | --- | --- |
| `ALERT_RETRY_CRON` | `*/5 * * * *` | Cron UTC del worker de reintentos (`alert-retry`). |
| `ALERT_RETRY_MAX_ATTEMPTS` | `4` | Intentos totales por mensaje, incluyendo el envío inicial. |
| `ALERT_RETRY_BASE_DELAY_SECONDS` | `30` | Base del backoff exponencial. |
| `ALERT_RETRY_JITTER_RATIO` | `0.25` | Jitter ± aplicado a cada espera de reintento. |

Cuando se agotan los intentos, el mensaje pasa a `dead_letter` y se puede
reprocesar manualmente:

```bash
curl -X POST -H "X-API-Key: $KEY" \
  "http://localhost:8000/alerts/dlq/replay?channel=webhook&limit=50"
```

### Reglas de envío (por objetivo)

```yaml
alerts:
  enabled: true             # por defecto true
  on_new_observables: true  # alertar cuando haya observables nuevos
  min_risk_level: high      # alertar si el riesgo es alto o crítico aunque no haya nuevos
  include_values: true      # false para omitir los valores de observables del payload
```

### Esquema JSON del webhook

> ⚠️ **Privacidad**: con `include_values: true` (por defecto) el payload
> contiene valores de observables como nombres de dominio, direcciones IP y
> correos electrónicos. Ponga `include_values: false` para enviar sólo conteos
> y tipos.

```json
{
  "target_id":            "example-domain",
  "target_fqdn":          "example.com",
  "run_id":               42,
  "run_status":           "success",
  "risk_level":           "high",
  "new_observables": [
    {"stix_type": "domain-name", "value": "sub.example.com", "stix_id": "domain-name--<uuid>"}
  ],
  "new_observable_count": 1,
  "report_path":          "/app/daily_reports/2026-09-08/example-domain/report.md",
  "finding_summary":      "Newly exposed subdomain detected.",
  "generated_at":         "2026-09-08T08:03:21.456789Z"
}
```

**Verificación de la firma** — cada petición lleva
`X-Orchestrator-Signature: sha256=<hex>`. Verifíquela en el receptor:

```python
import hashlib, hmac

def verify_signature(body: bytes, header: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)
```

---

## Retención

Los registros antiguos y los directorios `daily_reports/` se eliminan
automáticamente mediante un job nocturno en segundo plano.

| Variable | Por defecto | Descripción |
| --- | --- | --- |
| `ORCHESTRATOR_RETENTION_DAYS` | `90` | Días que se conservan los datos. `0` desactiva la retención. |
| `ORCHESTRATOR_RETENTION_CRON` | `30 3 * * *` | Expresión cron UTC para el job de purga. |

> **Cumplimiento:** `90` es un valor operativo, no un plazo regulatorio. Si
> estos reportes integran evidencia de debida diligencia de un sujeto obligado
> uruguayo, el art. 15 del Decreto 379/018 establece un mínimo de cinco años.
> Configure un plazo compatible (por ejemplo, `1825` días como piso sujeto a
> revisión profesional) o archive los artefactos en almacenamiento externo
> controlado antes de la purga.

El job elimina filas de `runs`, `run_observables`, `findings`, `alerts`,
`alert_deliveries` y `opencti_outbox` cuyo `finished_at` (o `started_at` para
runs que nunca terminaron) sea anterior al umbral. La tabla
`seen_observables` **nunca** se toca; es la memoria del delta entre
ejecuciones.

Los directorios con formato `daily_reports/YYYY-MM-DD` anteriores al umbral
también se borran.  Los directorios con nombre no-fecha se dejan intactos.

---

## Autenticación de la API (Fase 5)

Todos los endpoints salvo `GET /`, `GET /docs`, `GET /openapi.json`,
`GET /redoc`, `GET /health`, `GET /metrics`, `GET /console` y `GET /console/i18n.json` exigen
una clave de
API. Se envía como `X-API-Key: <clave>` o `Authorization: Bearer <clave>`.

```bash
ORCHESTRATOR_API_KEY=            # Generar: openssl rand -hex 32
                                 # dos claves separadas por coma durante una rotación
```

```bash
curl -H "X-API-Key: $ORCHESTRATOR_API_KEY" http://localhost:8000/targets
```

Una `ORCHESTRATOR_API_KEY` vacía deja la API **abierta** y registra una
advertencia al arrancar — sirve en una laptop, no en ningún otro lado. Los
rechazos son `401` con un `detail` localizado y `WWW-Authenticate: Bearer`. El
razonamiento (por qué una clave estática y no OAuth) está en
[ADR-005](docs/adr/ADR-005-api-auth-and-single-instance-es.md).

**Rotar una clave** sin ventana de corte: liste la vieja y la nueva juntas
(`ORCHESTRATOR_API_KEY=vieja,nueva`), reinicie, mueva a todos los clientes a la
nueva, y luego quite la vieja y reinicie otra vez. Las claves se comparan en
tiempo constante y se verifican todas en cada petición, así que un rechazo
tarda lo mismo sin importar qué posición habría coincidido.

---

## Observabilidad (Fase 5)

### Logs

```bash
ORCHESTRATOR_LOG_LEVEL=INFO      # DEBUG | INFO | WARNING | ERROR
ORCHESTRATOR_LOG_FORMAT=text     # text | json
```

Con `json`, cada línea es un objeto que un recolector de logs indexa sin regex:

```json
{"ts":"2026-09-08T08:03:21.456Z","level":"INFO","logger":"orchestrator.pipeline","msg":"Pipeline done: target=example-domain run_id=42 status=success new_observables=3","target_id":"example-domain","run_id":42,"status":"success","new_observables":3,"collectors":["openosint","spiderfoot"]}
```

Cada petición HTTP lleva un id (envíe el suyo en `X-Request-ID` o se genera
uno), devuelto en la cabecera de respuesta y estampado en cada línea de log
emitida mientras se atiende. Los logs de acceso y error de uvicorn usan el
mismo formato. Las corridas en segundo plano lanzadas por el scheduler
registran `-`, así que una línea sin id de petición es una corrida programada y
no una correlación perdida.

### Métricas

`GET /metrics` sirve métricas Prometheus (sin clave de API; se desactiva con
`ORCHESTRATOR_METRICS_ENABLED=false`). Todos los nombres llevan el prefijo
`osint_orchestrator_` y los valores de las etiquetas están acotados — nunca el
valor de un observable ni un id de ejecución.

| Métrica | Etiquetas | Significado |
| --- | --- | --- |
| `http_requests_total` | `method`, `path` (plantilla de ruta), `status` | Tráfico de la API |
| `http_request_duration_seconds` | `method`, `path` (plantilla de ruta) | Latencia de la API — sin etiqueta `status`, así que no se puede desglosar por código de respuesta |
| `runs_total` | `target_id`, `status` | Ejecuciones completadas por estado final (`success`, `partial`, `failed`) |
| `runs_in_progress` | `target_id` | Ejecuciones en curso |
| `run_duration_seconds` | `target_id` | Histograma de duración del pipeline completo |
| `collector_runs_total` | `collector`, `target_id`, `outcome` | Resultado por recolector (`success`, `failure`, `error`) |
| `collector_duration_seconds` | `collector` | Duración por recolector — sin etiqueta `target_id`, así que no se puede desglosar por objetivo |
| `run_observables` | `target_id`, `kind` (`total`, `new`) | Observables de la ejecución más reciente |
| `new_observables_total` | `target_id` | Observables nuevos e ingestados (la definición de alerta/delta) |
| `target_last_success_timestamp_seconds` | `target_id` | Timestamp de última corrida exitosa (usar `time() - métrica` para edad de frescura) |
| `opencti_ingest_total` | `target_id`, `outcome` | Bundles STIX enviados a OpenCTI |
| `opencti_ingest_retries_total` | `target_id` | Reintentos tras un error transitorio de OpenCTI (los reintentos internos por objeto de pycti no se cuentan) |
| `opencti_outbox_pending` | — | Bundles pendientes de OpenCTI en cola de reintento |
| `opencti_outbox_oldest_age_seconds` | — | Edad del bundle pendiente más antiguo en outbox |
| `opencti_outbox_deliveries_total` | `outcome` | Resultados del outbox (`sent`, `failed`, `dead_letter`) |
| `opencti_outbox_retries_total` | `target_id` | Intentos de reintento del outbox OpenCTI |
| `opencti_outbox_dead_letter` | — | Bundles OpenCTI aparcados en la DLQ (requieren acción del operador) |
| `alert_deliveries_pending` | — | Entregas de alertas a la espera de reintento |
| `alert_deliveries_dead_letter` | — | Entregas de alertas aparcadas en la DLQ (requieren acción del operador) |
| `synthesis_total` | `target_id`, `status` (`ok`, `skipped`, `failed`) | Intentos de síntesis LLM |
| `llm_requests_total` | `provider`, `model`, `status` | Solicitudes al API LLM por proveedor (`anthropic`, `openai`, `nebius`, `ollama`), modelo y estado (`ok`, `http_429`, `http_5xx`, `timeout`, `error`, `schema_downgrade`). Una muestra por llamada al SDK: el único reintento interno del SDK de Anthropic no se muestrea. |
| `llm_tokens_total` | `provider`, `model`, `direction` (`input`, `output`) | Uso de tokens LLM por proveedor y modelo, separado por dirección (prompt vs completion) |
| `llm_model_available` | `provider`, `model`, `route` (`reasoning`, `fast`) | Gauge del preflight de arranque: `1` cuando el modelo configurado para esa ruta aparece en `GET /models` del proveedor, `0` cuando no lo sirve |
| `alerts_total` | `channel`, `status` | Eventos del ciclo de alertas (`sent`, `failed`, `retried`, `dlq`) |
| `scheduled_jobs` | — | Jobs cron registrados en el scheduler |
| `build_info` | `version` | Metadatos de la build |

Tres alertas que conviene tener primero:

```promql
# Una ejecución falló por completo en el último día
increase(osint_orchestrator_runs_total{status="failed"}[1d]) > 0

# Los hallazgos están llegando a OpenCTI
increase(osint_orchestrator_opencti_ingest_total{outcome="failure"}[1h]) > 0

# El scheduler se quedó sin jobs (targets.yaml ilegible al arrancar)
osint_orchestrator_scheduled_jobs == 0
```

Paquete inicial de SLO operativos:

```promql
# Edad de frescura por objetivo (segundos desde la última corrida exitosa)
time() - osint_orchestrator_target_last_success_timestamp_seconds

# Semáforo de salud: 0=fresh (<24h), 1=stale (>=24h)
(time() - osint_orchestrator_target_last_success_timestamp_seconds) >= bool 86400

# Ratio de éxito de 7 días por objetivo
sum by (target_id) (increase(osint_orchestrator_runs_total{status="success"}[7d]))
/
sum by (target_id) (increase(osint_orchestrator_runs_total[7d]))
```

---

## Guías de negocio

- [Presentación ejecutiva del proyecto](docs/business/presentacion-ejecutiva-orquestacion-osint.es.md) · [Inglés](docs/business/executive-project-presentation.md)

Índice completo de documentación: [`docs/README.md`](docs/README.md).

---

## Kubernetes (Fase 5)

El chart de Helm en [`deploy/helm/osint-orchestrator`](deploy/helm/osint-orchestrator/)
despliega solo el orquestador; OpenCTI, SpiderFoot y Ollama se despliegan con
sus propios charts y se referencian por URL.

```bash
helm upgrade --install osint-orchestrator deploy/helm/osint-orchestrator \
  --namespace osint --create-namespace -f my-values.yaml
```

> El orquestador es **de instancia única por diseño** (SQLite + scheduler en
> proceso): `replicaCount` se queda en 1, la estrategia es `Recreate` y un
> único volumen `ReadWriteOnce` guarda la base y los reportes diarios. En
> [ADR-005](docs/adr/ADR-005-api-auth-and-single-instance-es.md) está el
> disparador que cambiaría esto.

El [README del chart](deploy/helm/osint-orchestrator/README.md) cubre los
secretos (`existingSecret`), el ConfigMap de `targets.yaml`, el
`ServiceMonitor` de Prometheus y los valores que realmente se cambian.

---

## Desarrollo

```bash
# Instalar dependencias de desarrollo (descarga el fork de openosint; requiere git)
pip install -e ".[dev]"

# Linter
ruff check orchestrator/ tests/unit/
ruff format --check orchestrator/ tests/unit/

# Tests unitarios (sin Docker)
pytest tests/unit/ -v

# Tests de integración (requiere docker compose up)
pytest tests/integration/ -m integration -v

# Chart de Helm
helm lint deploy/helm/osint-orchestrator --strict
helm template osint deploy/helm/osint-orchestrator --kube-version 1.30.0 > /dev/null
```

`--strict` es lo que corre CI: un lint sin esa bandera puede pasar en local y
bloquear el PR igual. `--kube-version` hace falta porque el chart declara
`kubeVersion: >=1.25.0-0` y `helm template` asume por defecto una versión más
antigua.

Flujo de contribución y convenciones:
[`CONTRIBUTING.es.md`](CONTRIBUTING.es.md).

### Estructura del repositorio

```text
orchestrator/
  api.py               App FastAPI, rutas, middleware de id de petición
  auth.py              Dependencia de clave de API (X-API-Key / Bearer)
  config.py            pydantic-settings — el contrato de variables de entorno
  database.py          Motor async y fábrica de sesiones
  i18n.py              Textos para el operador, es + en (ADR-004)
  logging_config.py    Formateadores text/JSON, contextvar del id de petición
  metrics.py           Colectores Prometheus
  models.py            Tablas SQLModel + esquema de targets.yaml + contrato CollectorResult v1.0
  pipeline.py          recolectar → normalizar → ingestar → sintetizar → reportar → alertar
  scheduler.py         Jobs cron de APScheduler construidos desde targets.yaml
  collectors/          openosint, spiderfoot, socialosint, amass
  normalizer/stix.py   hallazgos → bundle STIX 2.1 con ids deterministas
  sinks/__init__.py    Ingesta vía pycti: sonda de auth, reintento sólo de transitorios, fuera del loop
  synthesizer/         Proveedores LLM: ollama, anthropic, compatible con OpenAI
  reports/             report.md, index.md, PDF opcional
  alerts/              Envío por webhook y SMTP
deploy/helm/           Chart de Kubernetes
docs/adr/              Decisiones arquitectónicas (inglés + español)
tests/unit/            No requieren Docker
tests/integration/     Requieren el stack levantado; marcador: integration
```

Convenciones: ruff con `E,F,I,UP,B,SIM,N` y línea de 100 caracteres; `pytest`
en `asyncio_mode = auto`; dependencias git fijadas por SHA completo de commit e
imágenes Docker por etiqueta explícita, nunca `:latest`.

---

## Migraciones de base de datos

El orquestador utiliza [Alembic](https://alembic.sqlalchemy.org/) para gestionar las migraciones de esquema.
El servicio aplica todas las migraciones pendientes automáticamente **en cada arranque** — no requiere pasos manuales en operación normal.

### Cómo funciona

- Los scripts de migración se encuentran en `orchestrator/migrations/versions/`.
- Al arrancar, `create_db_and_tables()` ejecuta `alembic upgrade head`.
- Las **bases de datos existentes** sin tabla `alembic_version` (creadas antes de introducir Alembic) se marcan automáticamente en la revisión base antes de cualquier actualización, por lo que no se pierden datos.

### Generar una nueva migración

Después de modificar un SQLModel en `orchestrator/models.py`:

```bash
# Aplicar primero todas las migraciones actuales.
alembic upgrade head

# Generar una migración a partir del diff entre modelos y el esquema en vivo.
alembic revision --autogenerate -m "add my_new_column to runs"
```

Revise el archivo generado en `orchestrator/migrations/versions/` y ajuste si es necesario.

### Aplicar migraciones manualmente

```bash
alembic upgrade head          # aplicar todas las migraciones pendientes
alembic current               # ver la revisión actual
alembic history --verbose     # listar todas las revisiones
alembic downgrade -1          # revertir un paso
```

### Verificación en CI

El pipeline de CI ejecuta `alembic upgrade head` sobre una base de datos SQLite temporal y luego
`alembic check` — esto falla la compilación si se cambia un modelo sin la migración correspondiente.

---

## Diagnóstico

| Síntoma | Causa y solución |
| --- | --- |
| Elasticsearch se apaga a los segundos de `docker compose up` | `vm.max_map_count` por debajo de 262144 en el host — véase [Hardware](#requisitos-de-hardware) |
| `curl :8080/health` rechazado los primeros minutos | OpenCTI y Elasticsearch tardan 2–3 min; siga `docker compose logs -f opencti` |
| El OOM killer mata contenedores | Host por debajo de 16 GB, o `ELASTIC_MEMORY_SIZE` demasiado alto para él |
| `401` en todas las llamadas | `ORCHESTRATOR_API_KEY` está definida pero falta la cabecera o es incorrecta; `/health` y `/metrics` nunca la necesitan |
| La API responde sin clave | `ORCHESTRATOR_API_KEY` está vacía — el log de arranque lo dice explícitamente |
| `404` en `/metrics` | `ORCHESTRATOR_METRICS_ENABLED=false` |
| `400` en `POST /targets/{id}/run` | El objetivo existe pero está `enabled: false` |
| `pip install -e .` no resuelve `openosint` | La dependencia es un pin `git+https`, así que hace falta un cliente git en el `PATH` |
| Un escaneo de SpiderFoot no termina nunca | Suba el `timeout_seconds` del objetivo; compruebe que los módulos sean módulos `sfp_*` reales de esa imagen |
| La corrida es `partial` con `opencti-sink:` en `error` | El bundle nunca llegó a OpenCTI — revise `osint_orchestrator_opencti_ingest_total{outcome="failure"}`, `OPENCTI_URL` y `OPENCTI_ADMIN_TOKEN`; los observables se reportan como nuevos en la corrida siguiente |
| Los informes salen en el idioma equivocado | `ORCHESTRATOR_LANGUAGE`, o el `language` del objetivo; un valor no reconocido se registra y se ignora |
| Una corrida termina sin finding / crece `synthesis_total{status="failed"}` | El endpoint LLM no es alcanzable — compose no incluye un servicio Ollama; revise `LLM_BASE_URL` o cambie `LLM_PROVIDER` (véase [Inicio rápido](#2-arrancar-el-stack)) |
| La síntesis siempre sale como no disponible | Revise en el arranque `LLM model not served by provider` y si `osint_orchestrator_llm_model_available{...} == 0`; cambie a un id listado por `GET /models` del proveedor |
| El login en el navegador entra en bucle o da `502` en `:8002` con el overlay de auth | Keycloak aún no está healthy, o `AUTH_PROXY_PORT`/`AUTH_REDIRECT_URL` no coinciden — ambos deben usar el mismo puerto (`.env.example` trae 8002) |
| Un `cron` modificado no surte efecto | Las expresiones cron se registran al arrancar — reinicie el orquestador |
| `osint_orchestrator_scheduled_jobs` es menor de lo esperado | Un objetivo está `enabled: false`, o su `cron` no tiene cinco campos — ambos se omiten, el segundo con un log `ERROR` |
| `osint_orchestrator_scheduled_jobs` es 0 | No se encontró `targets.yaml` en `TARGETS_FILE` al arrancar (un `WARNING` indica la ruta) |

---

## Fases

| Fase | Estado | Descripción |
| --- | --- | --- |
| **0** | ✅ Completada | ADRs, pyproject, CI, docker-compose, `/health` |
| **1** | ✅ Completada | Recolector OpenOSINT (en proceso vía `investigate()`) → normalizador STIX → ingesta en OpenCTI con IDs STIX deterministas y conformes a la spec |
| **2** | ✅ Completada | Recolector SpiderFoot + scheduler + reportes diarios (`report.md`, `bundle.stix.json`, `delta.json`, `report.pdf` opcional, `index.md` diario) |
| **3** | ✅ Completada | Síntesis LLM (Ollama / Anthropic / OpenAI) por objetivo |
| **4a** | ✅ Completada | Corrección de observables vistos (#8), endpoint delta desde la base (#10), alertas por webhook y email |
| **4b** | ✅ Completada | Recolector SocialOSINT (HTTP, opt-in) + stack MISP real + `connector-misp` |
| **5** | ✅ Completada | Autenticación por clave de API, logs JSON + ids de petición, `/metrics` Prometheus, chart de Helm |

---

## Decisiones arquitectónicas

- [ADR-001: Monolito Modular](docs/adr/ADR-001-modular-monolith-es.md)
- [ADR-002: STIX 2.1 como Contrato de Datos Interno](docs/adr/ADR-002-stix-as-contract-es.md)
- [ADR-003: OpenCTI como Única Fuente de Verdad](docs/adr/ADR-003-opencti-as-store-es.md)
- [ADR-004: Español para Operadores, Inglés para Código](docs/adr/ADR-004-language-policy-es.md)
- [ADR-005: Claves de API estáticas, observabilidad estructurada y despliegue de instancia única](docs/adr/ADR-005-api-auth-and-single-instance-es.md)
- [ADR-006: Proxy OIDC opcional como capa de perímetro](docs/adr/ADR-006-oidc-proxy-es.md)

Cada ADR tiene su original en inglés junto al archivo `-es.md`.

---

## Notas sobre las herramientas

- **openosint**: fijado al fork [`careb36/OpenOSINT`](https://github.com/careb36/OpenOSINT) (MIT), **no** la versión de PyPI. El recolector llama a `openosint.investigate.investigate()` — la API pública Python documentada para consumidores downstream — que el upstream 2.27.0 de PyPI no incluye. La dependencia está fijada por commit para que un push al fork no pueda cambiar silenciosamente lo que resuelve una build; actualícela de forma deliberada. Al ser una referencia git, `pip install` necesita un cliente git (el Dockerfile instala uno).
- **SpiderFoot**: construido localmente desde el repositorio GitHub upstream (`smicallef/spiderfoot`, rama por defecto — no se descarga ninguna imagen de registro; el resultado se etiqueta `spiderfoot:local`). Puerto 5001. Sin prefijo `/api/v1/` — los endpoints están en la ruta raíz (`/startscan`, `/scanstatus`, etc.). Como el contexto de build sigue una rama y no una etiqueta, los rebuilds pueden incorporar cambios de upstream; fije el contexto a un commit (`context: https://github.com/smicallef/spiderfoot.git#<sha>`) si necesita reproducibilidad.
- **OWASP SocialOSINT**: código fuente en [bm-github/owasp-social-osint-agent](https://github.com/bm-github/owasp-social-osint-agent). El punto de entrada es CLI + modo JSON (sin API HTTP independiente). Se integra en la Fase 4b.
- **OWASP Amass**: imagen oficial `owaspamass/amass:v5.1.1` (Apache-2.0), fijada por etiqueta. El engine corre como sidecar; su API HTTP sólo gestiona sesiones, así que los resultados se leen con `oam_subs` desde la base de datos SQLite de activos del volumen compartido (la imagen del orquestador copia `oam_enum`/`oam_subs` de la misma imagen upstream). `-silent` en `oam_subs` también silencia los nombres, por eso el recolector sólo lo pasa a `oam_enum`.
- **MISP**: a través del [conector oficial OpenCTI↔MISP](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/misp). No hay código de conector propio en este repositorio.
- **TheHive**: la v4 está discontinuada; TheHive 5 es comercial. No incluido pendiente de evaluación de licencia.

---

## Licencia

MIT — véase [LICENSE](LICENSE).

## Documentos del proyecto

[CONTRIBUTING](CONTRIBUTING.es.md) · [SECURITY](SECURITY.es.md) · [CHANGELOG](CHANGELOG.md) · [Índice de documentación](docs/README.md)

---

## Ejecución en Nebius Token Factory + NVIDIA Nemotron

1. Defina `LLM_PROVIDER=nebius`.
2. Cargue su clave en `NEBIUS_API_KEY`.
3. Mantenga `NEBIUS_BASE_URL=https://api.tokenfactory.nebius.com/v1` salvo que su equipo de cuenta indique otro endpoint.
4. Elija modelos:
   - `LLM_MODEL_REASONING` para síntesis y razonamiento intensivo de relaciones, por ejemplo `nvidia/nemotron-3-super-120b-a12b` (o `nvidia/Nemotron-3-Ultra-550b-a55b`).
   - `LLM_MODEL_FAST` para clasificación/extracción rápida, por ejemplo `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` (o `nvidia/Nemotron-3_5-Lightning`).
   - Los ids distinguen mayúsculas y el catálogo cambia; liste los que admite su clave con `curl -H "Authorization: Bearer $NEBIUS_API_KEY" https://api.tokenfactory.nebius.com/v1/models`. Un id que no figure ahí hace fallar toda síntesis.
   - Si alguna queda vacía, se usa `LLM_MODEL`.
5. Ejecute la stack habitual (`docker compose up -d --build`; la imagen instala el extra `llm`, que trae el SDK `openai` que necesita este proveedor — una instalación local con `pip` necesita `pip install -e ".[llm]"`) y valide el pipeline de siempre (`POST /targets/{id}/run`, luego `/runs/{id}/finding`).

Notas:
- Nebius usa el mismo camino proveedor compatible con OpenAI que `openai` (sin código de integración duplicado).
- Las llamadas de síntesis usan la ruta de razonamiento.
- Se solicita primero `response_format` con esquema JSON; si el proveedor lo rechaza (400/422) se repite la misma petición sin él, contada como `schema_downgrade` y no como intento fallido, y la respuesta pasa por el parser JSON tolerante.
- Reintentos: hasta 3 intentos ante 408, 409, 429, cualquier 5xx y errores de transporte, respetando `Retry-After`, todo dentro de `LLM_TIMEOUT_SECONDS`: el presupuesto acota cada intento y cada espera de una llamada.
- El hallazgo registra el proveedor (`openai`, `nebius`, `anthropic`, `ollama`, el mismo valor que la etiqueta `provider` de las métricas) y el modelo que realmente atendió la petición (`/runs/{id}/finding`).
