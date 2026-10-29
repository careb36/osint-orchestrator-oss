# Skill: redaccion-natural-rae

Skill de agente para redactar y revisar en español el texto que este proyecto
publica en español: claves `es` de `orchestrator/i18n.py`, cuerpos de informe,
asuntos y cuerpos de alertas, la síntesis del LLM y `README.es.md`.

## Activación

Se carga por su descripción cuando la tarea consiste en redactar, corregir o
auditar un texto en español. En clientes que la invocan por nombre:

`redaccion-natural-rae Revisa este informe y conserva todos los identificadores y cifras.`

## Qué no hace

- **No decide el idioma.** El reparto entre inglés y español lo fija
  [ADR-004](../../../docs/adr/ADR-004-language-policy.md): código, comentarios,
  logs, commits, `README.md`, `docs/` y ADR van en inglés y esta skill no los
  toca. Si hay conflicto, manda `AGENTS.md`.
- **No traduce.** Revisa un texto en el idioma en que está escrito.
- **No garantiza resultados de detectores de IA** ni simula autoría humana, y no
  elimina avisos de autoría exigidos por una política.

## Contenido

| Fichero | Para qué |
| --- | --- |
| [`SKILL.md`](SKILL.md) | Procedimiento completo: alcance, principios, revisión lingüística, señales de estilo artificial y adaptación por género |
| [`references/control-editorial.md`](references/control-editorial.md) | Lista de verificación final y ejemplos comentados |
| [`references/fuentes-rae.md`](references/fuentes-rae.md) | Fuentes académicas, qué cubre cada una y protocolo de consulta |

Las fuentes se enlazan para consulta; no se copian fragmentos de las obras de la
RAE y la ASALE.
