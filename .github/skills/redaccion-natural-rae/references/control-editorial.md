# Control editorial y ejemplos

## Lista de verificación final

- [ ] ¿El documento cumple el objetivo y responde a su destinatario?
- [ ] ¿Todos los datos relevantes coinciden con la fuente?
- [ ] ¿Se preservan incertidumbres, condiciones y alcances?
- [ ] ¿Los términos técnicos mantienen el mismo significado?
- [ ] ¿Hay concordancia, sintaxis y puntuación correctas?
- [ ] ¿Se distinguen normas académicas de preferencias de estilo?
- [ ] ¿Se eliminaron introducciones vacías y redundancias?
- [ ] ¿Los conectores expresan relaciones reales?
- [ ] ¿La extensión y el formato son adecuados?
- [ ] ¿Hay afirmaciones nuevas sin respaldo?

## Comprobaciones propias de este repositorio

Añadir estas cinco a la lista cuando el texto viva en este proyecto. Ninguna
depende del estilo: cada una rompe algo si se salta.

- [ ] ¿El texto que se corrigió era realmente español? Comprobar el idioma
      resuelto (`resolve_language()`), no el idioma por defecto del proyecto.
      El código, `docs/`, `README.md` y los ADR van en inglés.
- [ ] ¿Sobrevivieron los marcadores de formato (`{qualified}`, `{collected}`,
      `{target}`, `{error}`) sin renombrar ni reordenar?
- [ ] ¿Siguen en inglés los valores que se persisten o se comparan
      (`risk_level`, `RunStatus`, tipos STIX)?
- [ ] ¿Se editó la pareja `es`/`en` de la misma clave y no una sola?
- [ ] ¿Se respetó el orden de secciones del informe
      (`_markdown_content`) en lugar de reordenarlo por criterio estilístico?

## Ejemplos orientativos

**Antes:** «Es importante destacar que se llevó a cabo la realización de un
análisis exhaustivo de los registros, lo que permitió evidenciar una serie de
oportunidades de mejora».

**Después:** «Se analizaron los registros y se identificaron aspectos que
requieren revisión».

**Cuidado:** «exhaustivo» solo puede omitirse si no es un alcance formalmente
definido; «requieren revisión» solo es válido si se desprende de la fuente.

**Antes:** «En este sentido, resulta fundamental señalar que el sistema estaría
presentando una problemática relacionada con las credenciales».

**Después, si solo existe un indicio:** «Se observó un fallo de acceso. Aún no se
confirmó si está relacionado con las credenciales».

**Antes:** «La implementación de la nueva solución permitirá optimizar los
tiempos y garantizar una experiencia robusta y eficiente».

**Después, si los beneficios no fueron medidos:** «Se propone implementar la
solución. Su impacto en los tiempos de respuesta deberá evaluarse».

## Qué no hacer

- No inventar errores gramaticales, expresiones coloquiales o faltas de
  ortografía para disimular la asistencia de IA.
- No falsear fuentes o referencias.
- No eliminar avisos de autoría o declaraciones exigidas por políticas
  institucionales, académicas o contractuales.
- No convertir una preferencia estilística en una prohibición normativa.
- No sustituir precisión técnica por un español artificialmente sencillo.
