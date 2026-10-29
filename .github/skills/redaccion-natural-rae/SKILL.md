---
name: redaccion-natural-rae
description: Redacta, corrige y reescribe documentos en español natural, preciso y profesional conforme a criterios de la RAE y ASALE. Úsala para documentación técnica, informes, actas, correos, memorandos, documentación de software y textos institucionales; para eliminar fórmulas artificiales, redundancias y tono genérico sin alterar hechos. No usar para falsificar autoría ni ocultar información cuya declaración sea obligatoria.
---

# Redacción natural y normativa en español

## Propósito

Escribir y revisar documentos en español correcto, idiomático y verosímil,
adaptados al destinatario y al género documental. Evitar patrones formularios y
artificiosos frecuentes en textos automáticos. **No** afirmar que un texto es
«indetectable», ni simular experiencia personal, fuentes o autoría humana que no
consten.

## Alcance dentro de este repositorio

Esta skill **no** cambia qué se escribe en cada idioma; para eso manda
[ADR-004](../../../docs/adr/ADR-004-language-policy.md) y, si hubiera conflicto,
`AGENTS.md`. Antes de aplicar cualquier corrección, ubicar el texto:

| Dónde está el texto | Idioma | Qué hacer |
| --- | --- | --- |
| Código, comentarios de código, logs, mensajes de commit, `README.md`, `docs/**`, ADR | Inglés | No traducir ni «mejorar» el español de un texto inglés. Esta skill no aplica |
| `targets.example.yaml`, comentarios incluidos | Español | Es el fichero que edita el operador a mano; ADR-004 lo asigna al español. Excepción explícita a la fila anterior. `.env.example` **no** entra: el ADR lo deja en inglés por ser un fichero de despliegue |
| `detail` de los errores de la API (`HTTPException`) | `es` y `en` | Prosa que lee el operador; va en el catálogo como una clave más |
| Claves de `orchestrator/i18n.py` y `ui/src/i18n.tsx` | `es` y `en` | Aplicar **solo a la variante cuyo idioma resuelto sea `es`** |
| Cuerpos de informe, asuntos y cuerpos de alertas, síntesis del LLM | El que resuelva `resolve_language()` | Aplicar solo si el idioma resuelto es `es`; ver la nota de abajo |
| `README.es.md` | Español | Aplicar, y mantenerlo con las mismas secciones que `README.md` |

El idioma de salida **no es fijo**. `resolve_language(preferred)` en
`orchestrator/i18n.py` toma primero el `language` del objetivo, después
`ORCHESTRATOR_LANGUAGE` y solo al final `es`; un valor desconocido se registra y
se salta en lugar de abortar la ejecución. Por eso el mismo cuerpo de informe
puede salir en inglés para un objetivo y en español para otro: antes de corregir
un texto generado, mirar el idioma resuelto, no el idioma por defecto del
proyecto. Las claves de `i18n.py` se editan por pareja, nunca una sola.

Reglas que se derivan de eso:

- **Cada clave de `i18n.py` lleva `es` y `en`.** Al retocar una cadena en un
  idioma, revisar la pareja: `test_catalogue_is_complete` y
  `test_every_translation_takes_the_same_placeholders` fallan si falta una
  traducción o si una cambia los marcadores de formato. El catálogo del panel
  (`ui/src/i18n.tsx`) tiene su propio control en `ui/src/i18n.test.ts`; editarlo
  sin pasar ese test deja la interfaz con una clave suelta.
- **Lo que se persiste o se compara no se traduce**: `risk_level` (`low`,
  `medium`, `high`, `critical`, `unknown`), `RunStatus`, tipos STIX y valores
  de enum siguen en inglés en los dos idiomas. Traducirlos rompe comparaciones y
  la correspondencia con OpenCTI.
- **Placeholders intactos.** `{qualified}`, `{collected}`, `{target}` y demás
  marcadores de formato se conservan literalmente; cambiar su nombre o su
  número rompe el formateo en tiempo de ejecución.
- **El texto en español de este repo es neutro y formal.** No introducir
  regionalismos ni voseo en cadenas de producto, aunque el destinatario sea
  rioplatense: el registro de la interfaz es uniforme para todos los operadores.

## Principios de actuación

1. **Fidelidad primero.** Preservar hechos, fechas, responsables, nombres
   propios, identificadores, decisiones, cifras, requisitos, citas, rutas,
   comandos y terminología técnica. No inventar ni completar vacíos con
   conjeturas. Marcar las lagunas relevantes como `[Dato pendiente de confirmar]`
   o consultar si la tarea lo permite.
2. **Normativa académica.** Aplicar la *Nueva gramática de la lengua española*
   (RAE-ASALE) a la morfología, la sintaxis y la concordancia. Para ortografía,
   signos y dudas léxicas, consultar los recursos académicos complementarios de
   `references/fuentes-rae.md`. No atribuir a la Gramática reglas que provengan
   de otras obras.
3. **Español panhispánico por defecto; variedad regional solo si el documento
   la pide.** El texto de producto de este proyecto (claves `es` de
   `orchestrator/i18n.py`, cuerpos de informe, alertas) está escrito en español
   neutro y formal, tratando al lector de usted: «Revise los campos», «Se
   evaluaron 5 de 7 evidencias». Mantener ese registro al editar esas cadenas.
   Si el documento tiene un destinatario regional identificable, respetar su
   variedad; no introducir voseo donde el resto del texto no lo usa ni corregir
   variedades válidas por gusto.
4. **Claridad con rigor.** Preferir sujeto, verbo y complemento claros; términos
   concretos; párrafos con una idea principal; relaciones causales explícitas
   cuando estén acreditadas. Evitar simplificaciones que modifiquen el alcance
   técnico o jurídico.
5. **Naturalidad sin trucos.** No introducir errores deliberados, muletillas,
   anécdotas inventadas o informalidad para «parecer humano». La calidad del
   texto es el objetivo; no la evasión de detectores.
6. **Economía expresiva.** Eliminar redundancias y solemnidad innecesaria.
   Mantener la extensión apropiada para el documento; no recortar detalles
   indispensables.
7. **Formato conservador.** En documentos existentes, conservar títulos,
   numeración, enlaces, tablas, marcas, citas, etiquetas y sintaxis
   Markdown/XWiki/HTML a menos que el usuario pida cambios estructurales.

## Procedimiento obligatorio

### 1. Identificar el encargo

Determinar silenciosamente el tipo de texto, destinatario, propósito, nivel de
formalidad, variante lingüística, formato y límites de edición. Si falta un dato
no esencial, elegir un supuesto razonable sin añadir afirmaciones fácticas.

### 2. Separar hechos de estilo

Antes de reescribir, localizar y proteger:

- nombres, fechas, cifras, estados, versiones, identificadores, rutas y vínculos;
- referencias a normativa, sistemas, contratos, expedientes o incidencias;
- afirmaciones que expresen certeza, hipótesis, recomendación o asunto pendiente;
- citas textuales y vocabulario de dominio.

**No transformar** «se evalúa», «se propone» o «podría» en «se aprobó», «se
implementó» o «se garantiza». No cambiar obligaciones («debe») por sugerencias
(«conviene») ni a la inversa.

### 3. Redactar con estructura documental real

- Elegir encabezados funcionales, no promocionales.
- Abrir con el asunto o resultado relevante, no con un párrafo ceremonial.
- Ordenar antecedentes, situación, análisis y acción según el género, sin imponer
  la misma plantilla a todo.
- Usar enumeraciones solo si ayudan a localizar información; cuando corresponda,
  preferir prosa conectada.
- Variar longitud y estructura de oraciones por claridad, no por un patrón
  artificial.
- Dar a cada párrafo una función reconocible.

### 4. Revisar la corrección lingüística

Comprobar al menos:

- concordancia sujeto-verbo y sustantivo-adjetivo;
- tiempos verbales, modo, correlación temporal y perífrasis;
- régimen preposicional, queísmo/dequeísmo y pronombres;
- referentes inequívocos, coordinación y subordinación;
- tildes, mayúsculas, abreviaturas, siglas y extranjerismos;
- comas, dos puntos, punto y coma, comillas y rayas;
- separación de proposiciones, precisión léxica y cohesión.

Ante una duda normativa real, consultar fuentes académicas accesibles y citar la
página o apartado específico si el usuario pide justificación. Si no se puede
consultar, no inventar una norma ni un número de apartado.

### 5. Revisar naturalidad: señales de alerta, no prohibiciones absolutas

Evaluar y reemplazar **cuando no aporten significado** expresiones como:

- «Es importante destacar que...», «Cabe mencionar que...», «Resulta fundamental
  señalar que...»;
- «En el contexto actual...», «En un mundo cada vez más...», «En este sentido...»
  repetido;
- «Sin lugar a dudas», «de vital importancia», «robusto», «integral», «óptimo»,
  «innovador» sin respaldo;
- «No solo..., sino también...» en serie;
- «En conclusión...» o «Por último...» cuando la estructura no lo pide;
- «permite potenciar», «brinda la posibilidad de», «llevar a cabo» donde un verbo
  directo sea más preciso;
- párrafos con longitud y cadencia casi idénticas;
- listas simétricas de tres elementos sin motivo; cierres ceremoniales automáticos.

No eliminar una expresión por aparecer en esta lista si es natural, necesaria o
técnicamente exacta. No tratar estos rasgos como prueba del origen del texto.

### 6. Control de consistencia factual

Comparar el texto final con el material de origen. Confirmar que no haya:

- información agregada sin fuente;
- cambios de responsables, fechas, estados o alcances;
- inferencias presentadas como hechos;
- pérdida de restricciones, excepciones o advertencias;
- sustitución indebida de nombres de sistemas y términos definidos.

### 7. Entrega

- Si se solicita **redactar**: entregar directamente el documento terminado, sin
  introducciones explicativas.
- Si se solicita **corregir o reescribir**: entregar la versión revisada. Añadir
  una nota breve solo cuando existan cambios sustantivos, ambigüedades o datos
  por comprobar.
- Si se solicita **auditar estilo o norma**: enumerar hallazgos concretos,
  propuesta y fundamento verificable, distinguiendo error normativo de
  preferencia editorial.
- No escribir «he eliminado toda huella de IA» ni prometer resultados de
  detectores.

## Adaptación por tipo de documento

### Documentación técnica y de software

Usar terminología consistente, preservar nombres de clases, métodos, endpoints,
tablas, versiones, logs, códigos de error y rutas. Describir qué ocurre, en qué
condición, con qué efecto y qué queda pendiente. No convertir observaciones en
diagnósticos no demostrados. Preferir «El servicio devuelve HTTP 403» a «Se
evidencia una problemática en la capa de autenticación» si solo consta la
respuesta HTTP.

### Informes ejecutivos para dirección no técnica

Es el caso de uso más frecuente en este repositorio (el informe periódico del
estado de los sistemas). El orden de las secciones **no es libre**: lo fija
`orchestrator/reports/__init__.py::_markdown_content` y forma parte del contrato
con el operador. Es cabecera → síntesis → evidencias cualificadas → novedades
desde la ejecución anterior → errores → anexo técnico. La razón está en el
docstring: primero las preguntas del lector (qué pasó, cuánto importa, qué
cambió) y al final el material de verificación.

Reglas que se derivan de eso:

- **La valoración va delante, pero nunca suelta.** La síntesis abre el informe
  y las evidencias que la sostienen vienen después; si una afirmación de la
  síntesis no tiene debajo una evidencia que la respalde, sobra la afirmación,
  no el orden.
- **No inventar un semáforo.** Los informes no tienen verde/amarillo/rojo:
  exponen `risk_level` con cinco valores (`low`, `medium`, `high`, `critical`,
  `unknown`) y un `synthesis_status` (`ok`, `skipped`, `failed`). Usar esos
  valores tal cual, sin traducirlos y sin sustituirlos por adjetivos.
- **Decir cuándo no hubo valoración.** Si la síntesis no se ejecutó
  (`skipped`, sin proveedor configurado) o falló (`failed`), el informe lo
  declara en su sección. Un texto que describa un riesgo cuando no hubo
  síntesis contradice el documento.
- **Sin jerga sin traducir.** Si hace falta un término técnico, definirlo la
  primera vez en la misma frase; no dejarlo como abreviatura suelta (`PR`,
  `CI`, `ADR`, `STIX`) sin explicación.
- **Decisiones pendientes con nombre y consecuencia.** Qué se decide, quién lo
  decide y qué pasa si no se decide. Una lista de temas abiertos sin
  consecuencia no permite decidir.
- **No atribuir causas no demostradas.** «El servicio devolvió 502 durante 40
  minutos» es un hecho; «por un problema de infraestructura» es una hipótesis
  hasta que conste.

### Informes institucionales y administrativos

Tono sobrio, preciso e impersonal cuando corresponda. Distinguir antecedentes,
hechos comprobados, evaluaciones y propuestas. Evitar énfasis retórico,
atribuciones de responsabilidad no documentadas y expresiones que impliquen
aprobación sin evidencia.

### Correos profesionales

Asunto preciso, apertura breve, motivo explícito, solicitud o conclusión
concreta, cierre proporcionado. No imponer frases de cortesía excesivas ni un
tono grandilocuente.

### Materiales académicos

Explicar conceptos con rigor y progresión didáctica. Preferir ejemplos pertinentes
y verificables; diferenciar definición, explicación y ejercicio. Mantener
denominaciones y criterios de evaluación originales.

## Jerarquía de criterios cuando hay conflictos

1. Integridad factual e instrucciones expresas del usuario.
2. Convenciones obligatorias del ámbito o plantilla documental.
3. Normas académicas pertinentes y usos panhispánicos admitidos.
4. Claridad, naturalidad, concisión y preferencias estilísticas.

Si un estilo institucional entra en conflicto con una recomendación de claridad,
no modificar automáticamente convenciones obligatorias; señalar la tensión
cuando sea importante.

## Referencias internas

Consultar `references/fuentes-rae.md` para las fuentes y alcances;
`references/control-editorial.md` para el control de calidad y ejemplos. No copiar
grandes fragmentos de obras académicas: parafrasear y enlazar.
