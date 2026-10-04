# ADR-007: Manifiestos de evidencia firmados por ejecución y encadenados por objetivo

> 🇬🇧 [English](ADR-007-evidence-chain.md)

**Estado:** Aceptada (2026-09-27)
**Fecha:** 2026-09-23
**Responsable de la decisión:** careb36

---

## Contexto

Cada ejecución del pipeline escribe sus artefactos en
`daily_reports/<YYYY-MM-DD>/<target_id>/`: `report.md`, `bundle.stix.json`,
`delta.json` y, cuando hay un backend de PDF disponible, `report.pdf`
(`orchestrator/reports/__init__.py`). La tabla `runs` registra cuándo ocurrió
la ejecución, qué recolectores corrieron, cuántos observables fueron nuevos y
dónde está el informe. Hoy nada demuestra que los archivos en disco son los que
produjo la ejecución, ni que ningún informe del historial de un objetivo fue
alterado o eliminado después. Para las audiencias a las que apunta este
proyecto (cumplimiento, AML, preparación forense — ver `docs/business/`) esa
brecha es la diferencia entre "un informe" y "evidencia".

`ORCHESTRATOR_SECRET_KEY` existe en `orchestrator/config.py` (valor por
defecto `insecure-dev-key`) y nada lo lee. La hoja de ruta arrastra una línea
"Fase 6 — cadena de evidencia" desde el ADR-005 sin un diseño.

## Decisión

### 1. Un manifiesto por ejecución

Después de escribir los artefactos de una ejecución, el pipeline escribe
`manifest.json` en el mismo directorio:

```json
{
  "manifest_version": 1,
  "run_id": 42,
  "target_id": "example",
  "started_at": "2026-09-23T08:00:00+00:00",
  "finished_at": "2026-09-23T08:07:12+00:00",
  "status": "success",
  "collectors_run": ["openosint", "spiderfoot"],
  "artefacts": {
    "report.md": "sha256:…",
    "bundle.stix.json": "sha256:…",
    "delta.json": "sha256:…",
    "report.pdf": "sha256:…"
  },
  "previous_manifest_sha256": "sha256:…",
  "signature": "hmac-sha256:…"
}
```

- `artefacts` enumera cada archivo que produjo la ejecución con su SHA-256. El
  ejemplo muestra una ejecución que produjo un PDF; cuando no hay backend de
  PDF disponible la clave `report.pdf` **no aparece**, nunca vale `null`. Los archivos se hashean
  después de estar completamente escritos, desde disco, nunca desde el
  contenido en memoria.
- `previous_manifest_sha256` es el SHA-256 del manifiesto de la **ejecución
  terminal anterior del mismo objetivo** (`runs.manifest_sha256`, ver §3), o
  `null` en la primera ejecución. Esto convierte manifiestos independientes en
  una cadena: eliminar o alterar cualquier manifiesto anterior rompe todos los
  eslabones posteriores.
- `signature` es un HMAC-SHA256 sobre el JSON canónico de todos los campos
  excepto `signature` (claves ordenadas, sin espacios, UTF-8), con
  `ORCHESTRATOR_SECRET_KEY` como clave. El SHA-256 del propio manifiesto (al
  que encadena la siguiente ejecución y el que guarda la base de datos) se
  calcula sobre el archivo final, firma incluida.

**Versionado.** `manifest_version` cambia solo cuando un verificador escrito
para la versión anterior ya no podría comprobar un manifiesto nuevo: otra
canonicalización, otro algoritmo de hash o de firma, o un cambio en el
significado de un campo existente. Añadir un campo no lo incrementa, porque la
firma cubre todos los campos presentes y un verificador canonicaliza lo que
lee. Los verificadores despachan según `manifest_version`, conservan todas las
versiones que alguna vez soportaron e informan una versión desconocida como
`unsupported_version`, nunca como manipulación. Los manifiestos nunca se
migran en el lugar.

### 2. Clave de firma

`ORCHESTRATOR_SECRET_KEY` pasa a ser la clave de firma. Conserva su nombre y
su valor por defecto, de modo que `.env.example` y las tablas de configuración
del README no cambian; con el valor por defecto el orquestador firma igual y
registra un WARNING al arrancar (`extra={"setting": "ORCHESTRATOR_SECRET_KEY"}`),
exactamente como se trata hoy un `ORCHESTRATOR_API_KEY` vacío.

Rotar la clave no invalida la cadena de hashes, pero tras una rotación
**todos** los manifiestos firmados antes informan `signature_key` hasta que el
verificador reciba la clave antigua. Es lo esperado, no ruido a suprimir: los
manifiestos nunca se vuelven a firmar, porque re-firmar reescribiría la
evidencia a posteriori y un auditor ya no podría saber qué clave respaldó una
ejecución en su momento. El procedimiento de rotación es entonces: guardar la
clave retirada fuera de línea, registrar la fecha de rotación y verificar las
ejecuciones anteriores contra la clave retirada fuera de línea (el formato del
manifiesto es autocontenido para eso). Un verificador multiclave integrado
queda fuera del alcance de este ADR.

### 3. Persistencia

La migración Alembic `0005` añade `manifest_sha256: str | None` a `runs`
(nullable, indexada). La columna permite que la API verifique la cadena de un
objetivo sin confiar en el sistema de archivos para los valores de enlace.

El manifiesto es el **último** archivo que escribe una ejecución, y
`manifest_sha256` se fija en la misma transacción que registra el estado final
de la ejecución. Una ejecución con `manifest_sha256` en `NULL` está *sin
sellar*: falló antes de escribir ningún artefacto, o después de escribir
algunos pero antes del manifiesto. Las ejecuciones sin sellar no son eslabones:
la siguiente ejecución sellada encadena con la última ejecución sellada
anterior, y sus directorios parciales quedan en disco para diagnóstico y los
elimina la retención como a cualquier otro. La verificación nunca trata una
ejecución sin sellar como manipulación; las cuenta aparte (`unsealed` en §4).

### 4. API (router protegido)

- `GET /runs/{run_id}/manifest` devuelve el manifiesto almacenado como JSON;
  404 (clave `i18n` `manifest.not_found`) cuando la ejecución no tiene uno.
- `GET /targets/{target_id}/chain/verify` recorre las ejecuciones terminales
  del objetivo en orden de `started_at` y, para cada una, recalcula los hashes
  de los artefactos en disco, comprueba la firma con la clave actual y
  comprueba `previous_manifest_sha256` contra el hash almacenado de la
  ejecución precedente. Respuesta:

  ```json
  {"ok": false, "checked": 12, "unsealed": 1, "first_broken_run_id": 37,
   "reason": "artefact_hash", "detail": "report.md"}
  ```

  `checked` cuenta las ejecuciones selladas, `unsealed` las omitidas según
  §3. `reason` ∈ `artefact_hash | artefact_missing | manifest_missing |
  signature | signature_key | chain_link | unsupported_version`. La
  verificación se detiene en el primer eslabón roto. El texto que ve una persona sale de
  `orchestrator/i18n.py` (`chain.reason.*`, `es` + `en`).

### 5. Observabilidad

Métrica `osint_orchestrator_evidence_chain_verify_total{target_id, outcome}`
(`outcome` ∈ `ok | broken | error`) en `orchestrator/metrics.py`, con su fila
en las tablas de métricas de ambos README. La línea de log que ya informa la
ruta del informe incorpora `manifest_sha256` en `extra`.

### 6. Lo que este ADR no hace

- No sella el tiempo contra una autoridad externa ni ancla los hashes en un
  ledger. La cadena demuestra consistencia interna y detecta ediciones
  posteriores; no demuestra ante un tercero *cuándo* se escribió un
  manifiesto. Un ADR posterior puede añadir sellos RFC 3161 sobre el mismo
  manifiesto.
- No cifra los artefactos ni restringe quién puede leerlos; el ADR-005 y el
  ADR-006 cubren el acceso.
- No firma el bundle STIX dentro de OpenCTI; OpenCTI sigue siendo la fuente
  de verdad de los *observables* (ADR-003), el sistema de archivos sigue
  siendo la fuente de verdad de los *informes*, y el manifiesto une ambos a
  través del hash del bundle.

## Consecuencias

- Un archivo nuevo por directorio de ejecución; la retención
  (`orchestrator/retention.py`) lo elimina junto con el directorio, y el
  endpoint de verificación informa las ejecuciones que ya no puede comprobar
  como `manifest_missing` y no como manipulación cuando su fila en `runs`
  también desapareció.
- El pipeline gana un paso síncrono tras la generación del informe (hashear
  unos pocos archivos); sin dependencias nuevas (`hashlib`, `hmac`, `json` de
  la biblioteca estándar).
- Los operadores obtienen una sola llamada para responder "¿se alteró algo en
  el historial de este objetivo?", y los auditores un manifiesto por
  ejecución que pueden verificar sin conexión con la clave y `sha256sum`.
- Tests que exige el issue de implementación: manifiesto determinista para
  entradas fijas; cambiar un byte de `report.md` rompe la verificación en esa
  ejecución con `artefact_hash`; verificar con otra clave informa
  `signature_key`; una ejecución que falla tras escribir `report.md` pero antes
  del manifiesto se cuenta en `unsealed` y la siguiente encadena saltándola; un
  manifiesto con `manifest_version: 99` informa `unsupported_version`; un
  objetivo sin ejecuciones verifica `ok` con
  `checked: 0`; `alembic check` limpio tras la migración `0005`.

## Enlaces

- [ADR-003: OpenCTI como única fuente de verdad](ADR-003-opencti-as-store-es.md)
- [ADR-005: Claves de API estáticas, observabilidad estructurada y despliegue de instancia única](ADR-005-api-auth-and-single-instance-es.md)
- [ADR-006: Proxy OIDC opcional como capa perimetral](ADR-006-oidc-proxy-es.md)
- `orchestrator/reports/__init__.py` — rutas de los artefactos
- `orchestrator/config.py` — `ORCHESTRATOR_SECRET_KEY`
