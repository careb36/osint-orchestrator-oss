# ADR-002: STIX 2.1 como Contrato de Datos Interno

> 🇬🇧 [English](ADR-002-stix-as-contract.md)

**Fecha:** 2026-09-04  
**Estado:** Aceptada

## Contexto

El orchestrator ingesta datos heterogéneos provenientes de múltiples herramientas OSINT (JSON/GraphML de OpenOSINT, eventos JSON de SpiderFoot, informes de SocialOSINT). Estos datos deben almacenarse en OpenCTI, que habla STIX 2.1 de forma nativa. Necesitamos un único formato canónico entre los recolectores, el normalizador y el sink.

## Decisión

Todos los intercambios de datos entre módulos utilizan **bundles STIX 2.1** (mediante la biblioteca Python `stix2`) como formato canónico.

Reglas:

1. Un `CollectorResult` (modelo Pydantic) transporta la salida bruta de la herramienta. **No sale** del normalizador.
2. El normalizador convierte cada `CollectorResult` en un `stix2.Bundle` con:
   - `confidence` (0–100, basado en una heurística de fiabilidad de la herramienta)
   - `x_opencti_score` (específico de OpenCTI, mismo rango)
   - `created_by_ref` apuntando a un objeto `Identity` por herramienta
   - `labels` que incluyen el nombre del objetivo
3. El sink (`sinks/opencti.py`) acepta únicamente objetos `stix2.Bundle`. Nunca analiza la salida bruta de los recolectores.
4. Ninguna cadena de texto ni diccionario cruza los límites de módulo — sólo modelos Pydantic tipados u objetos `stix2`.

## Consecuencias

- **Bueno:** la deduplicación es trivial — los IDs de STIX son deterministas (`stix2.utils.new_version` o hashing de `ExternalReference`). Ejecutar dos veces sobre los mismos datos produce los mismos IDs.
- **Bueno:** futuros sinks (MISP, ficheros planos) consumen los mismos bundles sin tocar los recolectores.
- **Malo:** el vocabulario STIX no mapea 1:1 con todos los tipos de observable OSINT. Los tipos sin mapeo se representan como objetos personalizados `x-opencti-`.
- **Malo:** la biblioteca `stix2` impone validación estricta de la spec; los datos inválidos lanzan error en tiempo de normalización, que es el modo de fallo correcto.
