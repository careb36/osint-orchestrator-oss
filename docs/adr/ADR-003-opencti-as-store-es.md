# ADR-003: OpenCTI como Única Fuente de Verdad

> 🇬🇧 [English](ADR-003-opencti-as-store.md)

**Fecha:** 2026-09-04  
**Estado:** Aceptada

## Contexto

El orchestrator necesita un almacén en grafo para los hallazgos OSINT, las relaciones y la inteligencia de amenazas. Opciones consideradas:

1. **BD de grafo dedicada (Neo4j, ArangoDB):** control total, pero duplica el grafo que OpenCTI ya mantiene internamente mediante Elasticsearch + relaciones.
2. **OpenCTI como almacén:** utilizar el grafo existente de OpenCTI y consultarlo vía GraphQL para la síntesis.
3. **Sólo SQLite:** simple pero sin traversal de grafo, sin pipeline nativo de importación STIX.

## Decisión

**OpenCTI es la única fuente de verdad para los hallazgos OSINT y sus relaciones.**

- El orchestrator nunca duplica objetos STIX en una segunda BD de grafo.
- Todas las consultas para síntesis (`synthesizer/`) llegan a la API GraphQL de OpenCTI vía `pycti`.
- El SQLite propio del orchestrator (o Postgres en producción) almacena **sólo estado operacional**: objetivos, historial de ejecuciones y hashes SHA-256 de IDs de observables ya ingestados (para deduplicación de nuevos hallazgos).
- La integración con MISP es gestionada por el conector oficial OpenCTI↔MISP (perfil Docker), no por código del orchestrator.

## Por qué no una BD de grafo dedicada

OpenCTI ya incluye Elasticsearch (para búsqueda de texto completo), Redis (caché), RabbitMQ (bus de mensajes) y MinIO (almacenamiento de ficheros). Añadir Neo4j consumiría 2–4 GB adicionales de RAM en una máquina que ya necesita 12+ GB para el stack base. El valor de una BD de grafo dedicada sólo se materializa cuando el modelo de datos diverge de STIX — que es precisamente lo que queremos evitar (véase ADR-002).

## Consecuencias

- **Bueno:** sin coste adicional de infraestructura.
- **Bueno:** la deduplicación integrada de OpenCTI gestiona objetos STIX duplicados por ID.
- **Bueno:** acceso gratuito al explorador visual de grafo y los dashboards de OpenCTI.
- **Malo:** las consultas de síntesis están limitadas a lo que OpenCTI expone vía GraphQL. Solución alternativa: usar GraphQL directo con la escotilla `CustomQuery` de `pycti`.
- **Malo:** el orchestrator no puede funcionar sin OpenCTI. Aceptado — OpenCTI es una dependencia central, no opcional.
