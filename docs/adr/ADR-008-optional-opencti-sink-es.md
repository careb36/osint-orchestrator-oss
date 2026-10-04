# ADR-008: Sink opcional de OpenCTI mediante OPENCTI_ENABLED

> 🇬🇧 [English](ADR-008-optional-opencti-sink.md)

**Fecha:** 2026-10-04  
**Estado:** Aceptada

## Contexto

El ADR-003 estableció OpenCTI como fuente única de verdad y lo trató como
dependencia no opcional. En la práctica, algunos despliegues no tienen
OpenCTI: una instalación liviana o una demo pública, o un operador que solo
quiere reportes, findings, delta y alertas. La recolección, los reportes y las
alertas tienen que funcionar ahí sin una instancia de OpenCTI.

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
- **No es un interruptor para caídas.** Mientras está deshabilitado, los
  observables se registran como vistos sin ingestarse, así que al volver a
  activar el sink el delta los considera conocidos: **nunca se reenvían** a
  OpenCTI. Una caída temporal o una ventana de mantenimiento de OpenCTI ya la
  resuelve el outbox (tabla `opencti_outbox`, settings `OPENCTI_OUTBOX_*`): los bundles
  fallidos se encolan y se reintentan sin perder nada. Pasar un despliegue de
  `false` a `true` hace que el grafo empiece desde ese momento; reingestar
  ejecuciones anteriores exigiría reproducir a mano sus `bundle.stix.json`.
