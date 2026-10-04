# ADR-006: Proxy OIDC opcional como capa perimetral

> 🇬🇧 [English](ADR-006-oidc-proxy.md)

**Estado:** Aceptada
**Fecha:** 2026-09-17
**Responsable de la decisión:** careb36

---

## Contexto

El [ADR-005](ADR-005-api-auth-and-single-instance-es.md) estableció claves de
API estáticas (`X-API-Key` o `Bearer`) como único mecanismo de autenticación de
la API. Esa decisión sigue siendo adecuada para un despliegue de instancia
única operado mediante automatizaciones y una clave precompartida.

Un requisito posterior pidió una experiencia de login web (usuario,
contraseña, cookie de sesión y cierre de sesión OIDC) delante de la consola,
sin cambiar el mecanismo de claves que ya usan los clientes automáticos.

## Decisión

El overlay opcional `docker-compose.auth.yml` añade dos servicios al stack:

1. **Keycloak** (`--profile auth`), proveedor OIDC/OAuth2 que importa el realm
   de `auth/keycloak/realm.json`. No se distribuyen usuarios de demostración;
   cada operador debe crear sus propias cuentas.
2. **oauth2-proxy** (`--profile auth`), proxy inverso de autenticación que
   valida sesiones OIDC antes de reenviar las peticiones a
   `http://orchestrator:8000` por la red de Docker Compose. Escucha en el host
   en `${AUTH_PROXY_PORT:-8002}`.

### Lo que el overlay no hace

- No reemplaza la autenticación por clave de API. Los clientes que envían
  `X-API-Key` continúan funcionando sin cambios.
- No es obligatorio. El stack base funciona sin el overlay y mantiene
  `127.0.0.1:8000` para acceso directo desde el host.
- No añade autorización granular ni RBAC: el acceso perimetral es
  autenticado o rechazado.

### Red

El overlay no usa `network_mode: host`. `auth-proxy` se conecta a la red de
Compose y accede al orquestador mediante el nombre del servicio
(`http://orchestrator:8000`). Keycloak queda accesible desde el navegador en
`http://localhost:${KEYCLOAK_PORT}` y desde el proxy mediante
`OIDC_ISSUER_URL`.

## Modelo de acceso desde navegador

Un navegador no puede adjuntar `X-API-Key` en la primera navegación y el token
OIDC que reenvía oauth2-proxy no es una clave de la API. Por lo tanto:

- `GET /console` y `GET /console/i18n.json` son públicos porque solo sirven el
  shell y sus traducciones, sin datos de objetivos ni ejecuciones. Las
  peticiones posteriores de la consola sí pasan por el router protegido con
  la clave que ingresa el operador, guardada en `sessionStorage`.
- Con el overlay, el proxy autentica a la persona y la clave autentica al
  cliente. La consola detrás del proxy sigue solicitando la clave.
- El proxy no inyecta la clave compartida en las peticiones upstream, para no
  convertir cada sesión web autenticada en portadora de ese secreto.

## Consecuencias

- Quien necesite login agrega `docker-compose.auth.yml` al comando de Compose
  y configura las variables de la sección de autenticación humana de
  `.env.example`.
- Se debe crear al menos un usuario en Keycloak después del primer arranque;
  no se incluyen credenciales de demostración.
- El ADR-005 sigue siendo la decisión canónica para claves de API. Este ADR
  añade un perímetro opcional y no sustituye ese contrato.

## Enlaces

- [ADR-005: claves de API, observabilidad e instancia única](ADR-005-api-auth-and-single-instance-es.md)
- [README: puerta de entrada autenticada opcional](../../README.es.md#puerta-de-entrada-autenticada-opcional-perfil-auth)
