# ADR-008: Sink opcional de OpenCTI mediante OPENCTI_ENABLED

> 🇬🇧 [English](ADR-008-optional-opencti-sink.md)

**Fecha:** 2026-10-04  
**Estado:** Aceptada

## Contexto

El ADR-003 estableció OpenCTI como fuente única de verdad y lo trató como
dependencia no opcional. En la práctica, también hace falta un modo liviano
para demos, ventanas de mantenimiento o caídas temporales de OpenCTI donde la
recolección, los reportes y las alertas continúen sin ingestar en OpenCTI.

## Decisión

Introducir `OPENCTI_ENABLED` (por defecto `true`) como switch de ejecución:

- `true`: comportamiento actual (ingesta en OpenCTI y worker de reintentos del outbox).
- `false`: omitir la ingesta en OpenCTI y omitir el replay/registro del worker del outbox.

Cuando está deshabilitado, las ejecuciones del pipeline siguen produciendo
reportes/findings/delta/alertas y no deben marcarse como parciales solo porque
se omitió la ingesta en OpenCTI.

## Consecuencias

- El ADR-003 sigue siendo la arquitectura por defecto para producción
  (`OPENCTI_ENABLED=true`).
- Con `OPENCTI_ENABLED=false`, OpenCTI deja de ser el sink activo de ese
  despliegue; por ello el grafo de conocimiento de OpenCTI (y los flujos que
  dependen de él, como intercambios vía conectores) queda intencionalmente no disponible.
- Este modo es útil operativamente, pero debe tratarse como una postura
  degradada del grafo de conocimiento, no como reemplazo del ADR-003.
