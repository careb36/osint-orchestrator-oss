# Política de Seguridad

> 🇬🇧 [English](SECURITY.md)

## 1. Uso autorizado (la regla más importante)

Este orquestador lanza **reconocimiento activo** (peticiones DNS, TLS y HTTP
vía SpiderFoot; pivoteo sobre fuentes públicas vía OpenOSINT; análisis
opcional de redes sociales vía SocialOSINT) contra lo que esté listado en
`targets.yaml`.

- Añada únicamente objetivos que le **pertenezcan** o para los que tenga
  **autorización escrita**.
- `authorization` y `purpose` son obligatorios por objetivo y se escriben en
  el informe de cada corrida como pista de auditoría de por qué se realizó la
  recolección.
- El repositorio no incluye nada que explote, autentique contra, o interactúe
  de cualquier otro modo con un objetivo más allá de la recolección de fuentes
  públicas. No añada ese tipo de código, ni siquiera en tests o fixtures.
- La recolección está acotada por diseño: los presupuestos de OpenOSINT
  (`max_depth`, `max_entities`, `max_tool_calls`) y el `timeout_seconds` de
  SpiderFoot evitan escaneos descontrolados contra infraestructura de
  terceros.

## 2. Reportar una vulnerabilidad

**No abra un issue público en GitHub para una vulnerabilidad de seguridad.**

Reporte en privado mediante el formulario *Report a vulnerability* de GitHub
(Security → Advisories → "Report a vulnerability" en
`careb36/osint-orchestrator-oss`), o por e-mail al propietario del repositorio.
Incluya:

- versión / SHA de commit afectada,
- pasos de reproducción o prueba de concepto,
- evaluación de impacto,
- si el problema ya es público.

Apuntamos a acusar recibo en **5 días hábiles** y a publicar un advisory con
la corrección. Los arreglos de seguridad se liberan y se referencian en
[CHANGELOG.md](CHANGELOG.md).

## 3. Modelo de seguridad y checklist de endurecimiento

| Capa | Mecanismo | Referencia |
| --- | --- | --- |
| Acceso a la API | Clave de API estática compartida (`X-API-Key` / `Bearer`), comparación en tiempo constante, rotación listando dos claves | [ADR-005](docs/adr/ADR-005-api-auth-and-single-instance-es.md) |
| Login humano (opcional) | Front door OIDC con Keycloak + oauth2-proxy (`--profile auth`) | [ADR-006](docs/adr/ADR-006-oidc-proxy-es.md) |
| Alertas webhook | Firma HMAC-SHA256 del payload (`X-Orchestrator-Signature`) cuando `ALERT_WEBHOOK_SECRET` está definida | README → Alertas |
| Métricas | Valores de etiquetas acotados; nunca el valor de un observable, un id de corrida ni una cadena de error | README → Observabilidad |
| Logs | Logs JSON con ids de petición; no se registra material sensible | `orchestrator/logging_config.py` |
| Retención | Purga nocturna de corridas/informes tras `ORCHESTRATOR_RETENTION_DAYS` (90 por defecto) | README → Retención |

El valor por defecto de 90 días es operativo. No debe interpretarse como plazo
legal: cuando los artefactos formen parte de evidencia LA/FT, configure el
plazo exigible o use un archivo externo controlado (véase el art. 15 del
Decreto 379/018 y la sección Retención del README).

Antes de cualquier despliegue fuera de una laptop:

- [ ] `ORCHESTRATOR_API_KEY` definida (una clave vacía deja la API
      **abierta**; se registra una advertencia al arrancar).
- [ ] `OPENCTI_ADMIN_PASSWORD`, `MINIO_ROOT_PASSWORD`, `RABBITMQ_DEFAULT_PASS`,
      `ORCHESTRATOR_SECRET_KEY`, `KEYCLOAK_ADMIN_PASSWORD` cambiadas desde sus
      marcadores de posición.
- [ ] `ALERT_WEBHOOK_SECRET` definida si usa webhooks (sin ella los payloads
      van sin firmar).
- [ ] Puerto 8000 del host protegido por firewall o sin publicar cuando el
      front door de auth (8002) es el punto de entrada previsto.
- [ ] TLS terminado en un proxy/ingress real en producción; los defaults del
      overlay de auth son comodidades de desarrollo (`COOKIE_SECURE=false`,
      `network_mode: host`).
- [ ] Cuentas de demostración (Keycloak `analyst`/`change-me`) eliminadas o
      deshabilitadas.
- [ ] `.env` nunca commiteado; `targets.yaml` sin credenciales (no está
      cifrado y no es un almacén de secretos).

## 4. Protección de datos y privacidad

- Los payloads de alerta llevan valores de observables (dominios, IPs,
  correos) salvo que se configure `include_values: false` por objetivo —
  considere dónde los almacena el canal receptor.
- Los datos de SocialOSINT están sujetos a los términos de desarrollador de
  cada plataforma; X/Twitter en particular restringe almacenar y
  redistribuir datos de usuarios. Por eso el recolector es opt-in y su
  análisis LLM se guarda en OpenCTI etiquetado como *no verificado*.
- La síntesis LLM con `LLM_PROVIDER=ollama` mantiene los datos on-premises;
  los proveedores cloud (`anthropic`, `openai`) envían observables a un
  tercero — conviértalo en una decisión explícita y documentada en su
  jurisdicción.

## 5. Versiones soportadas

Solo la rama `main` actual (y los releases etiquetados cuando se publiquen)
recibe correcciones de seguridad. El proyecto es pre-1.0; los despliegues
fijan el SHA de commit exacto que ejecutan.
