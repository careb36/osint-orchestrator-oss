# Contribuir a OSINT Orchestrator

> 🇬🇧 [English](CONTRIBUTING.md)

Gracias por su interés en contribuir. Esta guía consolida las reglas que
están dispersas entre el README, los ADRs y
`AGENTS.md`. Cuando difieren, este archivo y los ADRs
ganan — y un PR que corrija la diferencia es bienvenido.

## Reglas de base

1. **Solo uso autorizado.** Esta herramienta hace reconocimiento activo. Nunca
   añada código, tests, fixtures o ejemplos que apunten a sistemas que no le
   pertenezcan o para los que no tenga autorización escrita. Véase
   [SECURITY.es.md](SECURITY.es.md) y la sección *Uso autorizado* del README.
2. **Lea el ADR relevante antes de cambiar la arquitectura**
   ([`docs/adr/`](docs/adr/)). No contradiga un ADR en el código sin proponer
   un ADR nuevo (o una enmienda) en el mismo PR.
3. **La política de idioma ([ADR-004](docs/adr/ADR-004-language-policy-es.md))
   no es negociable.** Código, comentarios, docstrings, logs, commits y PRs en
   inglés. El texto orientado al operador pasa por `orchestrator/i18n.py` con
   entradas `es` y `en` (CI verifica que el catálogo esté completo). Los
   identificadores persistidos (`risk_level`, `RunStatus`, tipos STIX) quedan
   siempre en inglés.

## Preparación del entorno

```bash
# Python 3.11+; se requiere git (openosint es una dependencia git fijada).
# pycti carga libmagic al importarse: instálela antes
# (macOS: brew install libmagic; Debian/Ubuntu: apt install libmagic1).
pip install -e ".[dev]"
# Opcional: los SDK de LLM en la nube (síntesis con openai/nebius/anthropic)
pip install -e ".[dev,llm]"

# Gates de calidad — los mismos comandos que corre CI
ruff check orchestrator/ tests/unit/
ruff format --check orchestrator/ tests/unit/
pytest tests/unit/ -v -m "not integration"

# Solo si tocó deploy/helm/ (ambas banderas importan; ver abajo)
helm lint deploy/helm/osint-orchestrator --strict
helm template osint deploy/helm/osint-orchestrator --kube-version 1.30.0 > /dev/null
```

Los tests de integración necesitan el stack completo de compose:
`docker compose up -d && pytest tests/integration/ -m integration -v`.

## Flujo de trabajo de un Pull Request

1. Cree la rama desde `main`. Un cambio lógico por PR.
2. Mensajes de commit en inglés, modo imperativo, con prefijo de alcance
   cuando aporte (`feat(alerts): …`, `docs(readme): …`, `fix(sink): …`).
3. Complete la plantilla de PR. El checklist de **Documentation impact** es
   obligatorio, no decorativo.
4. Pegue en la descripción del PR la salida de los gates de calidad. Un PR con
   lint en rojo o tests fallando no está listo para revisión.
5. Actualice un pin de dependencia (SHA git o tag de Docker) en un commit
   propio y explique por qué. Nunca `:latest`.

## Convenciones que los revisores hacen cumplir

- **Sesiones:** `orchestrator/database.py::get_session()` es la única forma de
  obtener una sesión de base de datos.
- **STIX:** los objetos STIX se construyen solo en
  `orchestrator/normalizer/stix.py`, con ids deterministas. Los recolectores
  devuelven `CollectorResult`; la salida cruda de una herramienta nunca sale
  del módulo del recolector.
- **Settings:** las variables nuevas van en `orchestrator/config.py` con el
  prefijo del componente (`ORCHESTRATOR_`, `OPENCTI_`, `ALERT_`, …), un
  comentario explicativo y una línea en `.env.example` (CI falla si hay claves
  sin documentar).
- **Tests:** pytest con `asyncio_mode = auto`, `pytest_httpx` para HTTP y un
  motor SQLite en memoria por test (copie el patrón `_make_engine` de
  `tests/unit/test_alerts.py`). Los tests nunca tocan el `orchestrator.db`
  real ni la red.
- **Secretos:** nada que parezca una credencial puede aparecer en
  `.env.example`, docs, fixtures o tests. Use valores vacíos con
  `# Generate: openssl rand -hex 32` o cadenas `<placeholder>`. GitGuardian
  escanea cada PR y un hallazgo lo bloquea.
- **Migraciones:** todo cambio en `orchestrator/models.py` llega con su
  migración Alembic (`alembic revision --autogenerate`); CI corre
  `alembic check`.

## Definition of Done documental

Un cambio no está terminado hasta que su documentación esté completa:

- Cambios de API → tablas de endpoints del README **y** README.es.
- Settings nuevos/cambiados → `.env.example` (con comentario inline) y las
  tablas de configuración del README.
- Cambios en flujos del operador → el README o la guía correspondiente en `docs/`.
- Los companions bilingües (`README.es.md`, ADR `-es.md`) se actualizan **en
  el mismo PR** que el archivo canónico en inglés.
- Los documentos de negocio llevan `**Última revisión:** YYYY-MM-DD`.

## Delegar una tarea a OpenCode

El trabajo rutinario y bien especificado se delega a
[OpenCode](https://opencode.ai), un agente de programación que corre dentro
del runner de GitHub Actions de este repositorio
(`.github/workflows/opencode.yml`) con el modelo y los permisos declarados en
`opencode.json`. Lee `AGENTS.md` antes de cada tarea; un mantenedor revisa y
mergea cada PR que abre, con los mismos gates que un PR humano.

### Prerrequisitos únicos (owner del repositorio)

1. Instalar la GitHub App
   [`opencode-agent`](https://github.com/apps/opencode-agent) en este
   repositorio (o ejecutar `opencode github install` desde un clon local).
2. Crear el secret de repositorio `DEEPSEEK_API_KEY` (*Settings → Secrets and
   variables → Actions*). La clave vive solo ahí; `opencode.json` la referencia
   como `{env:DEEPSEEK_API_KEY}`.
3. Recomendado: protección de la rama `main` que exija pull request y CI en
   verde, para que el agente (o cualquier bot) nunca pueda pushear a `main`
   directamente.

### Delegar una tarea

1. Abra un issue con la plantilla **Agent task**. Escríbalo de modo que cada
   paso numerado y cada test nombrado se pueda verificar contra el código: el
   issue *es* el test de aceptación. Nombre los archivos que el agente no debe
   tocar.
2. Comente `/oc` en el issue (opcionalmente seguido de una línea con
   instrucciones extra). Solo los comentarios cuyo autor es el **owner** del
   repositorio disparan el workflow; el `/oc` de cualquier otra persona se
   ignora.
3. El agente crea la rama `opencode/<issue>-<slug>`, la pushea y abre un PR
   que completa la plantilla de PR y pega la salida de los gates de calidad.
   CI corre sobre él como en cualquier otro PR.
4. Revíselo como siempre (ver abajo). Para pedir un seguimiento, envíe una
   review con ítems numerados y luego deje un **comentario** en el PR:
   `/oc Address every numbered item in the review above`. La review por sí
   sola no dispara al agente; el comentario sí.
5. Mantenga **una sola tarea delegada en vuelo a la vez** para que las ramas
   no diverjan de `main`.

### Qué verifica el revisor

Cada PR delegado pasa por el mismo gate, sobre un checkout limpio del head del
PR, antes de mergearse:

- `ruff check`, `ruff format --check`, `pytest tests/unit/`,
  `alembic upgrade head && alembic check` sobre una base de datos temporal, y
  los comandos de lint/render de Helm si cambió `deploy/helm/`.
- Cada ítem numerado y cada test del issue, verificados contra el código y no
  contra la descripción del PR.
- Guardas del repositorio: sin credenciales, `README.md`/`README.es.md` y los
  companions de los ADR siguen siendo espejos, tablas de métricas coincidentes
  con `orchestrator/metrics.py`, y `.gitignore`, workflows y `pyproject.toml`
  intactos salvo que el issue lo pidiera.

### Alternativa: ejecutar OpenCode localmente

Si el canal de Actions no está disponible, la misma tarea corre desde un clon:

```bash
export DEEPSEEK_API_KEY=<su clave>     # nunca la commitee
opencode run -m deepseek/deepseek-chat -f ruta/a/tarea.md \
  --title "issue-<n>" "Implement the task in the attached file"
```

Luego pushee la rama y abra el PR a mano. El gate de revisión es idéntico.

## Guarda de publicación

Este repositorio es público. Dos cosas nunca entran al árbol, en ningún
archivo, fixture, comentario ni mensaje de commit:

- **Credenciales** de cualquier tipo (ver *Secretos* más arriba).
- **Referencias a organismos públicos, reguladores o portales oficiales del
  Estado concretos.** Los documentos de negocio describen el contexto
  regulatorio en términos genéricos a propósito; manténgalo así. Las leyes y
  decretos pueden citarse por número.

Ejecute la guarda antes de abrir un PR; CI corre el mismo script y hace fallar
el PR ante un hallazgo:

```bash
bash scripts/check_public_release.sh              # árbol trackeado + gitleaks
CHECK_HISTORY=1 bash scripts/check_public_release.sh   # también el historial git
```

El patrón de referencias prohibidas vive solo en ese script. Amplíelo ahí.

### Uso responsable

La sección *Uso autorizado* del README y la sección 1 de
[SECURITY.es.md](SECURITY.es.md) forman parte de las reglas de contribución:
nunca añada objetivos, fixtures ni ejemplos que apunten a terceros reales,
nunca añada código que interactúe con un objetivo más allá de la recolección
de fuentes públicas, y mantenga todo dominio de ejemplo bajo `example.com` /
`example.org`.

## Problemas de seguridad

**No** abra un issue público para una vulnerabilidad. Siga el canal privado
de reporte en [SECURITY.es.md](SECURITY.es.md).

## Licencia

Al contribuir, acepta que sus contribuciones se licencian bajo la
[licencia MIT](LICENSE) del proyecto.
