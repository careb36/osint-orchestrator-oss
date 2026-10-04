# ADR-001: Arquitectura de Monolito Modular

> 🇬🇧 [English](ADR-001-modular-monolith.md)

**Fecha:** 2026-09-04  
**Estado:** Aceptada

## Contexto

El orchestrator necesita coordinar múltiples recolectores OSINT (OpenOSINT, SpiderFoot, SocialOSINT), un normalizador, un sink hacia OpenCTI, un sintetizador y un generador de informes. Debíamos elegir entre microservicios, un monolito modular o un monolito convencional.

El proyecto parte de un único desarrollador y cero usuarios en producción. Dividir en microservicios desde el primer día añade latencia de red, sobrecarga de trazabilidad distribuida, pipelines de despliegue independientes y autenticación entre servicios — todo coste sin beneficio cuando no existe presión de escalado todavía.

## Decisión

Desplegar el orchestrator como un **único proceso Python** (`orchestrator/`) con límites de módulo internos bien definidos:

- `collectors/` — un archivo por herramienta, cada uno implementando `BaseCollector`
- `normalizer/` — funciones puras, salida exclusivamente STIX 2.1
- `sinks/` — un archivo por destino (OpenCTI hoy, otros más adelante)
- `synthesizer/` — integración LLM, aislada detrás de una interfaz
- `reports/` — generación de artefactos, sin efectos secundarios sobre el modelo de datos

Los módulos se comunican únicamente a través de modelos Pydantic tipados (`CollectorResult`, `Finding`). Sin estado mutable compartido, sin importaciones cruzadas entre módulos fuera del pipeline `main` del orchestrator.

## Criterios de extracción (cuándo extraer un servicio)

Extraer un módulo como servicio independiente **sólo** cuando se cumpla una de las siguientes condiciones:

1. Un módulo necesita escalar de forma independiente (p. ej., los escaneos de SpiderFoot son intensivos en CPU y bloquean la generación de informes).
2. Un módulo necesita un lenguaje o runtime diferente.
3. Un módulo es consumido por una segunda aplicación.

Hasta entonces, el monolito es la unidad de despliegue.

## Consecuencias

- **Bueno:** un único `docker compose up`, un único flujo de logs, depuración sencilla, sin autenticación entre servicios.
- **Bueno:** refactorización sencilla — los límites de módulo se imponen mediante revisión de código, no mediante topología de red.
- **Malo:** un fallo en el bucle de recolectores tumba también el scheduler. Mitigado capturando excepciones por recolector y continuando.
- **Malo:** no es posible escalar los recolectores de forma independiente. Aceptado para v1.
