# Documentation index · Índice de documentación

> Bilingual index — English first, español abajo. · Índice bilingüe — primero
> inglés, español abajo.

Entry points: [README (EN)](../README.md) · [README (ES)](../README.es.md) ·
[CONTRIBUTING](../CONTRIBUTING.md) ([ES](../CONTRIBUTING.es.md)) ·
[SECURITY](../SECURITY.md) ([ES](../SECURITY.es.md)) ·
[CHANGELOG](../CHANGELOG.md)

## Architecture Decision Records (EN / ES)

| ADR | Topic |
| --- | --- |
| [ADR-001](adr/ADR-001-modular-monolith.md) · [ES](adr/ADR-001-modular-monolith-es.md) | Modular monolith |
| [ADR-002](adr/ADR-002-stix-as-contract.md) · [ES](adr/ADR-002-stix-as-contract-es.md) | STIX 2.1 as the internal data contract |
| [ADR-003](adr/ADR-003-opencti-as-store.md) · [ES](adr/ADR-003-opencti-as-store-es.md) | OpenCTI as the single source of truth |
| [ADR-004](adr/ADR-004-language-policy.md) · [ES](adr/ADR-004-language-policy-es.md) | Language policy (Spanish for operators, English for code) |
| [ADR-005](adr/ADR-005-api-auth-and-single-instance.md) · [ES](adr/ADR-005-api-auth-and-single-instance-es.md) | API-key auth, observability, single-instance deployment |
| [ADR-006](adr/ADR-006-oidc-proxy.md) · [ES](adr/ADR-006-oidc-proxy-es.md) | Optional OIDC front door (compose overlay) |

## Business and operator guides

| Document | Audience | Language |
| --- | --- | --- |
| [Executive project presentation](business/executive-project-presentation.md) · [ES](business/presentacion-ejecutiva-orquestacion-osint.es.md) | Management, compliance, AML officers | EN + ES |

## Technical guides and standards

| Document | What it covers |
| --- | --- |
| [SocialOSINT integration design](socialosint.md) | Collector architecture, platform credentials, LLM analysis flow |
| [Helm chart README](../deploy/helm/osint-orchestrator/README.md) | Kubernetes deployment values and secrets |
| [`scripts/render_business_pdf.py`](../scripts/render_business_pdf.py) | Renders any business doc to a formal PDF (cover + styled body): `python scripts/render_business_pdf.py docs/business/<doc>.md` |

---

## Español

Puntos de entrada: [README (ES)](../README.es.md) · [README (EN)](../README.md) ·
[CONTRIBUTING.es](../CONTRIBUTING.es.md) · [SECURITY.es](../SECURITY.es.md) ·
[CHANGELOG](../CHANGELOG.md)

- **Decisiones arquitectónicas (ADR):** tabla anterior; cada ADR tiene su
  versión `-es.md` enlazada.
- **Guías de negocio y operador:** tabla anterior (presentación ejecutiva).
- **Guías técnicas:** tabla anterior (diseño de SocialOSINT y chart de Helm).

Convención de idiomas: el archivo en inglés es canónico en READMEs y ADRs;
los companions en español son traducciones enlazadas desde la cabecera. Los
manuales de negocio pueden redactarse primero en español
([ADR-004](adr/ADR-004-language-policy-es.md), enmienda 2026-09-17).
