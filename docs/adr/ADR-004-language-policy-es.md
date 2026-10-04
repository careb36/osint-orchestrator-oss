# ADR-004: Español para Operadores, Inglés para Código

> 🇬🇧 [English](ADR-004-language-policy.md)

**Fecha:** 2026-09-04  
**Estado:** Aceptada

## Contexto

Los operadores de este despliegue trabajan en español. Los informes y la síntesis LLM los leen ellos, por lo que producir ese texto en inglés impone un paso de traducción en cada lectura de cada informe diario.

Al mismo tiempo, el proyecto no tenía una regla de idioma definida, y ya había derivado por ello: el commit `e51aa1a` incluyó una corrección etiquetada como "README language" cuyo contenido real era revertir un fragmento en español (`conector oficial`) que había filtrado hacia el diagrama de arquitectura. Una corrección sin una regla sólo aplaza la próxima deriva, y ahora hay dos agentes escribiendo en este repositorio.

Tres restricciones acotan la decisión:

1. **La dependencia está en inglés.** El recolector importa `openosint`, cuyo fork está siendo integrado en `OpenOSINT/OpenOSINT`, un proyecto público en inglés. Su vocabulario — `EntityGraph`, `Entity`, `budget` — llega a nuestros puntos de llamada independientemente de lo que hagamos.
2. **El vocabulario del dominio está en inglés.** STIX 2.1 y OpenCTI definen `domain-name`, `observable`, `relationship_type`, `x_opencti_score`. Son identificadores, no prosa, y traducirlos produciría datos inválidos.
3. **Algunas cadenas son datos, no texto.** `Finding.risk_level` se persiste, compara y filtra. Localizarlo en reposo rompería silenciosamente todas las comparaciones contra él.

## Decisión

El idioma se elige por **audiencia**, no por archivo o repositorio.

**Español — todo lo que una persona lee como prosa:**

- Informes diarios (Markdown y PDF)
- Síntesis LLM: `summary`, `risk_justification`, `suggested_pivots`
- Detalles de errores de la API (`HTTPException.detail`)
- Comentarios orientados al operador en `targets.example.yaml` — el archivo que el operador edita manualmente
  (`.env.example` permanece en inglés: es un archivo de despliegue cuyo contenido son variables de OpenCTI,
  Elasticsearch y RabbitMQ nombradas en inglés)

**Inglés — todo lo que lee un desarrollador o una máquina:**

- Código fuente: identificadores, comentarios, docstrings
- Mensajes de log — aparecen junto a trazas de error y salida de bibliotecas en inglés, y se leen durante la depuración, no durante la operación
- Mensajes de commit, descripciones de PR, ADRs, README
- Valores de enumeraciones e identificadores que se persisten o comparan: `RunStatus`, `CollectorName`, `Finding.risk_level`, tipos y nombres de propiedad STIX

### Mecanismo

`orchestrator/i18n.py` contiene un catálogo de mensajes indexado por id de mensaje y luego por idioma. `t(key, language=..., **kwargs)` renderiza uno; `resolve_language()` escoge el idioma de la fuente más específica disponible:

```text
target.language  →  settings.orchestrator_language (ORCHESTRATOR_LANGUAGE)  →  "es"
```

El ajuste se llama `orchestrator_language`, no `language`, y el prefijo es funcional, no cosmético: pydantic-settings deriva la variable de entorno del nombre del campo, por lo que un campo `language` a secas se vincularía a `LANGUAGE` — una variable estándar de GNU gettext exportada en la mayoría de hosts Linux y dentro de muchas imágenes de contenedor. El idioma de los informes seguiría entonces el locale del host, de forma silenciosa y sólo en algunos despliegues. `test_setting_ignores_the_hosts_gettext_language` mantiene eso bloqueado.

El override por objetivo replica el campo `llm:` existente, para el caso en que los informes de un objetivo van a un lector diferente.

Los idiomas soportados son `es` y `en`. Un valor no reconocido se registra y se omite en lugar de lanzar una excepción: un error tipográfico en `targets.yaml` debe degradar a otro idioma, nunca tumbar una recolección programada.

## Consecuencias

**Bueno.** Los operadores leen los informes en su propio idioma sin un paso de traducción por informe. El código permanece contribuible y diferenciable respecto al upstream, y cualquier cosa que enviemos allí no necesita reescritura de idioma. La regla está escrita, por lo que la deriva de `e51aa1a` tiene un lugar donde resolverse en lugar de rediscutirse en cada revisión.

**Malo.** Las cadenas orientadas al operador deben pasar por `t()` en lugar de escribirse directamente, lo que supone un pequeño coste en cada nuevo mensaje y un punto más que un revisor debe verificar. Dos idiomas en el catálogo son dos oportunidades para actualizar sólo uno — mitigado por `test_catalogue_is_complete`, que falla la CI ante cualquier clave que falte una traducción.

**Diferido.** La localización de fechas y números no se aborda; se vuelve relevante cuando existan informes (Fase 2) y debe decidirse entonces, junto con el motor de plantillas. Añadir un tercer idioma implica auditar el catálogo, no cambiar el mecanismo.

## Alternativas consideradas

**gettext / archivos `.po`.** La respuesta estándar, y la correcta a una escala que este proyecto no tiene. Añade un paso de compilación y herramientas para un catálogo que actualmente contiene cuatro claves. Reconsiderar si el catálogo supera aproximadamente cincuenta.

**Español en todo, incluido el código.** Rechazado por la restricción 1: crea una frontera de idioma exactamente donde el orchestrator llama a OpenOSINT, y cualquier código contribuido posteriormente upstream necesitaría reescritura. Las trazas de error y el vocabulario STIX permanecen en inglés de todas formas, por lo que el resultado es mixto de todos modos — lo peor de ambos mundos.

**Inglés en todo, traducir en el lector.** Rechazado como el statu quo que motivó esto: transfiere trabajo manual recurrente a las personas para quienes existen los informes.

## Enmienda (2026-09-17): companions bilingües

La práctica fue más allá de la regla original: este README y estos ADR ahora
tienen companions en español (`README.es.md`, `*-es.md`) y los manuales de
negocio bajo `docs/business/` se redactan en español. Eso no viola "inglés
para desarrolladores", sino que es su consecuencia — decide el test de
*audiencia*:

- El **archivo en inglés es canónico** para READMEs y ADRs. Un companion
  (`README.es.md`, `-es.md`) es una traducción para operadores, stakeholders y
  revisores hispanohablantes, con enlace cruzado desde la cabecera del
  canónico.
- Los **manuales de negocio/operador** (`docs/business/*`) pueden redactarse
  primero en español, con companion en inglés cuando la audiencia lo requiera.
- Los companions deben actualizarse en el mismo PR que cambia el archivo
  canónico para que ambos idiomas describan el mismo comportamiento.
- Todo lo que la regla original asigna al inglés — código, comentarios,
  docstrings, logs, commits, identificadores persistidos — sigue en inglés sin
  excepción.
