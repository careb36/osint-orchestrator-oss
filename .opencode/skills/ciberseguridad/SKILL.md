---
name: Ciberseguridad y OWASP
description: Desarrollo seguro en cualquier proyecto de Dev: OWASP Top 10, modelado de amenazas con OWASP pytm, bandit/pip-audit o equivalentes, validación de entradas, rutas, red, secretos, salidas, LLM y evidencias.
---

# Ciberseguridad y OWASP

Usar esta skill al agregar o cambiar entradas, archivos, red, dependencias,
autenticación, APIs, prompts/LLM, contenedores o despliegue. Las compuertas se
ejecutan y se revisan; no se silencian.

Esta es la versión **portable** para los proyectos de `/home/caro/Dev`. Si el
proyecto tiene una skill local `ciberseguridad`, esa prevalece y esta sirve de
base.

## 1. Adaptar al proyecto

Antes de ejecutar, identificar el stack y las compuertas reales:

```bash
git rev-parse --show-toplevel
ls pyproject.toml package.json Makefile Dockerfile 2>/dev/null
grep -nE '^(security|threat-model|test|check):' Makefile 2>/dev/null
```

- Si existe `make threat-model`, usarlo.
- Si existe `make security`, usarlo.
- Si no existen, usar los equivalentes de la sección 2 y dejar registrado el
  comando exacto.
- El triaje va en `docs/threat_triage.md` (o `SECURITY_TRIAGE.md` si el
  proyecto ya usa esa convención). Si no existe, crearlo.

## 2. Compuertas mínimas

### Python

```bash
python -m bandit -r . -q
python -m pip_audit
```

Si el proyecto tiene modelo pytm:

```bash
python scripts/threat_model.py   # o make threat-model
```

### Node / TypeScript

```bash
npm audit --omit=dev
npm run lint                    # con reglas de seguridad si existen
```

### Contenedores / imágenes

```bash
trivy image <imagen>            # si está disponible
```

### Todos los stacks

```bash
# tests, build y validaciones del proyecto
make check        # si existe
# o: make test / npm test / pytest
```

`bandit`/`npm audit` deben quedar limpios o con cada hallazgo triado.
`pip-audit`/`npm audit` pueden reportar dependencias transitivas sin versión
compatible: se documenta el riesgo residual, la mitigación compensatoria y la
fecha de revisión. No se usa `|| true` para ocultar el resultado.

## 3. OWASP pytm (modelado de amenazas)

pytm es la herramienta OWASP en Python para modelar amenazas STRIDE a partir de
actores, límites de confianza, procesos, almacenes y flujos.

1. Instalar el extra o el paquete en el entorno de desarrollo:
   ```bash
   pip install pytm
   ```
2. Modelar el sistema en un script versionado (`scripts/threat_model.py`,
   `security/threat_model.py` o el que ya exista).
3. Generar el modelo y revisar el diff:
   ```bash
   python scripts/threat_model.py
   git diff -- docs/threat_model.json docs/threat_model.md docs/threat_triage.md
   ```
4. Clasificar **cada amenaza nueva** en el triaje como **Aplicable**,
   **Parcial** o **No aplicable**, con mitigación o justificación.

pytm es genérico: buffer overflow, SSI, LDAP, hardware y otras amenazas pueden
no aplicar. El valor está en el triaje explícito, no en el número total. No se
borran amenazas del modelo para “limpiar” el resultado.

Actualizar el modelo al agregar procesos, endpoints, datastores, límites de
confianza, salidas a internet o datos sensibles. Las amenazas de LLM se mapean
con OWASP LLM Top 10.

## 4. OWASP Top 10 → reglas concretas

| Riesgo | Regla |
|---|---|
| A01 Control de acceso | Autorización en el servidor, no en la UI; IDs y rutas validados; mínimo privilegio; APIs locales por defecto. |
| A02 Fallas criptográficas | TLS verificado; hash SHA-256 para integridad; nunca secretos en claro; no `verify=False` salvo excepción documentada. |
| A03 Inyección | Sin `shell=True`, `eval`/`exec` ni SQL concatenado; validar y escapar entradas; consultas parametrizadas. |
| A04 Diseño inseguro | Modelo de amenazas y triaje antes de exponer flujos; límites, timeouts y compuertas por diseño. |
| A05 Mala configuración | CSP, `nosniff`, `frame-ancestors`, sin debug en producción, bind local por defecto, permisos mínimos. |
| A06 Componentes vulnerables | Dependencias fijadas (`constraints.txt`, lockfile); auditar; extras opcionales; no agregar peso innecesario. |
| A07 Autenticación | Contraseñas/API keys con hash seguro; rate limit; sesión y Host validados; no confundir “nombre de operador” con autenticación. |
| A08 Integridad | Hashes de corpus/artefactos, citas literales, auditoría append-only, descargas verificadas. |
| A09 Registro y monitoreo | Logs sin secretos ni datos personales innecesarios; auditoría persistente; errores internos solo en log local. |
| A10 SSRF | Allowlist de dominios, TLS, timeouts, límite de tamaño, redirecciones validadas; no aceptar URLs arbitrarias. |

## 5. Patrones obligatorios

### Entradas y rutas

- Validar tipo, longitud, rango y formato en el borde de confianza.
- Unir rutas con un helper seguro (`safe_join_path` o equivalente) y validar
  nombres; nunca `os.path.join(base, dato_del_usuario)`.
- Escrituras atómicas (tmp + `os.replace`); archivos temporales con `tempfile`.
- No confiar en validaciones solo de la UI.

### Comandos y procesos

- `subprocess.run([...], shell=False, check=True, timeout=...)`.
- Sin `eval`, `exec`, `pickle` de datos no confiables ni `yaml.load` inseguro.
- No interpolar entrada en una línea de comandos.

### Red

- Toda URL pasa por una allowlist de esquema/host; sin IPs privadas ni
  credenciales embebidas.
- TLS verificado, timeouts, límite de bytes y validación del tipo de archivo.
- No aceptar URLs arbitrarias del usuario para descargar o abrir.
- Las integraciones externas (LLM, APIs, webhooks) respetan una compuerta de
  configuración explícita y no envían datos sensibles sin necesidad.

### Salidas

- Escapar HTML/atributos/JS/JSON según el contexto; no `innerHTML` con datos
  sin escapar.
- Errores genéricos al cliente; detalle solo en log/auditoría local.
- No incluir secretos, tokens, prompts crudos ni datos personales en reportes.

### Secretos

- Nunca en código, tests, logs, capturas, `.env` versionado ni git.
- Usar variables de entorno o un gestor; `.env.example` sin valores reales.
- Si se expone una clave: rotarla y revisar el historial.

### Dependencias

- Versiones fijadas en lockfile/constraints; extras opcionales.
- Auditar; actualizar la cadena si hay versión compatible.
- Si no hay versión compatible, documentar el residual y la mitigación; no
  silenciar la herramienta.

### LLM

- El modelo propone; una persona aprueba. No darle herramientas ni ejecutar su
  salida.
- Validar el JSON de salida; delimitar el contenido no confiable (prompt
  injection); redactar datos sensibles del prompt.
- Registrar el proveedor/modelo y la compuerta, no el prompt con PII.

## 6. Banderas rojas (no aprobar)

- `shell=True`, `os.system`, `eval`, `exec`, `pickle`/`yaml.load` inseguros.
- URL del usuario sin allowlist; `verify=False`; descargas sin límite.
- Rutas o comandos concatenados con datos del usuario.
- Secretos o tokens en el diff, logs o tests.
- HTML con `innerHTML` sin escapar; citas o evidencias inventadas.
- Aprobaciones automáticas o un LLM con permiso de escritura.
- `make security`/`pip-audit`/`npm audit` silenciados o amenazas borradas del
  modelo.

## 7. Definición de terminado

- [ ] Stack y comandos identificados; compuertas ejecutadas.
- [ ] Modelo pytm actualizado y diff revisado (si aplica).
- [ ] Amenazas nuevas triadas; ninguna *Aplicable* High/Critical sin
      mitigación, test o ADR.
- [ ] `bandit`/`npm audit` limpios o triados; `pip-audit` con residual
      documentado.
- [ ] Tests/build/`make check` verdes.
- [ ] Sin secretos ni PII innecesaria en el diff.
- [ ] Nuevas rutas, red, archivos, auth o LLM con control y test.
- [ ] Evidencia (modelo, triaje, tests) versionada con el cambio.

## 8. Reporte de hallazgos

Incluir severidad, archivo/línea, flujo de explotación, dato afectado,
mitigación, test que la cubre y riesgo residual con fecha de revisión. No
incluir secretos, tokens ni datos personales.

## 9. Límites

pytm modela el diseño, no ejecuta el sistema; bandit/eslint son análisis
estático; pip-audit/npm audit miran el entorno instalado, no el despliegue real.
Ninguna herramienta reemplaza la revisión manual ni una prueba de penetración.
Un riesgo aceptado debe estar escrito y firmado por quien decide.
