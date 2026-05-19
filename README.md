[![NPM package](https://img.shields.io/npm/v/mcp-oauth-server.svg?style=flat-square)](https://www.npmjs.com/package/mcp-oauth-server)

# mcp-oauth-server

OAuth 2.1 Authorization Server implementation built to support the [MCP Authorization Spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) through [@modelcontextprotocol/typescript-sdk](https://github.com/modelcontextprotocol/typescript-sdk).

Based on the MCP SDK’s partial OAuth 2.1 Authorization Server implementation.

## Table of Contents

- [Installation](#installation)
- [Features](#features)
- [OAuth client credentials](#oauth-client-credentials-machine-to-machine)
- [Device authorization (RFC 8628)](#device-authorization-rfc-8628)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
  - [OAuthServer](#oauthserver)
  - [OAuthServerModel](#oauthservermodel)
  - [mcpAuthRouter](#mcpauthrouter)
  - [authenticateHandler](#authenticatehandler)
  - [requireBearerAuth](#requirebearerauth)

## Installation

```bash
npm install mcp-oauth-server@latest --save-exact
```

## Features

- **MCP Authorization Spec compliant**: Aligns with the [MCP Authorization Spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
    - [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
    - Dynamic Client Registration [(RFC 7591)](https://datatracker.ietf.org/doc/html/rfc7591)
    - Token Revocation [(RFC 7009)](https://datatracker.ietf.org/doc/html/rfc7009)
    - Authorization Server Metadata [(RFC 8414)](https://datatracker.ietf.org/doc/html/rfc8414)
    - Protected Resource Metadata [(RFC 9728)](https://datatracker.ietf.org/doc/html/rfc9728)
- **Grant types**: Configurable via `grantTypes` — `authorization_code`, `refresh_token`, [`client_credentials`](#oauth-client-credentials-machine-to-machine), and [device authorization](https://datatracker.ietf.org/doc/html/rfc8628) (`urn:ietf:params:oauth:grant-type:device_code`)
- **Compatibility**: Works with MCP clients that omit a `resource` indicator [(RFC 8707)](https://datatracker.ietf.org/doc/html/rfc8707) or requested scopes when needed (`strictResource`)
- **Flexible storage**: In-memory model for development (`MemoryOAuthServerModel`) or your own `OAuthServerModel` for production

**Not supported:** Token introspection [(RFC 7662)](https://datatracker.ietf.org/doc/html/rfc7662) — validate access tokens via `OAuthServer.verifyAccessToken` (and `requireBearerAuth`) instead.

## OAuth client credentials (machine-to-machine)

Use this grant when **no end user** is present (services, CI, daemons). MCP documents this as the **OAuth Client Credentials** extension (`io.modelcontextprotocol/oauth-client-credentials`). See the official guide: **[OAuth Client Credentials](https://modelcontextprotocol.io/extensions/auth/oauth-client-credentials)**.

**Server**

1. Include `'client_credentials'` in `grantTypes`.
2. Clients registered for this flow must include `client_credentials` in `grant_types` (via dynamic registration or your model).

```ts
import { OAuthServer } from 'mcp-oauth-server';

const oauthServer = new OAuthServer({
    authorizationUrl: new URL('https://example.com/consent'),
    scopesSupported: ['mcp:tools'],
    grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
});
```

**Client (conceptually)**

`POST` to the token endpoint with `grant_type=client_credentials` and authenticate the client (for example `client_id` / `client_secret` per [RFC 6749 §4.4](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)). MCP clients using `@modelcontextprotocol/client` can use `ClientCredentialsProvider` as described in the extension docs above.

Tokens minted for this grant typically have **no `userId`** on `AuthInfo` — authorize by `clientId` and scopes where appropriate.

## Device authorization (RFC 8628)

Use the **device authorization grant** for clients that cannot easily run a browser redirect (CLIs, TVs, constrained devices).

**Server**

1. Set `deviceAuthorizationUrl` to the URL where the user enters or confirms the **user code** (your UX page).
2. Add the device grant type to `grantTypes` (use the exported constant so you do not typo the URN):

```ts
import { OAuthServer, DEVICE_AUTHORIZATION_GRANT_TYPE } from 'mcp-oauth-server';

const oauthServer = new OAuthServer({
    authorizationUrl: new URL('https://example.com/consent'),
    scopesSupported: ['mcp:tools'],
    grantTypes: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
    deviceAuthorizationUrl: new URL('https://example.com/device'),
});
```

3. Implement the device-related methods on `OAuthServerModel` (`saveDeviceAuthorization`, `getDeviceAuthorizationByDeviceCode`, `getDeviceAuthorizationByUserCode`, `deleteDeviceAuthorization`) — see `MemoryOAuthServerModel` for a reference.

The auth router exposes **`POST /device`** (under your AS base path) when the device grant and `deviceAuthorizationUrl` are configured. Metadata lists `device_authorization_endpoint` accordingly.

**Approving or denying a login**

Wire **`approveDeviceAuthorizationHandler`** and **`denyDeviceAuthorizationHandler`** on routes you choose; they accept `user_code` (and resolve the authenticated user via `getUser`) so the user can approve or reject the device login out-of-band.

## Quick Start

A working MCP OAuth example with a memory-backed authorization server lives in [`./example`](example).

**Run the demo**

1. Start the server:

   ```bash
   pnpm example:server
   ```

2. In another terminal, authenticate with the server:

   ```bash
   pnpm example:client
   ```

The example covers mounting the OAuth router, a simple consent screen, and confirming authorization.

## API Reference

### OAuthServer

OAuth 2.1 server instance passed to `mcpAuthRouter`.

```ts
import { OAuthServer } from 'mcp-oauth-server';

const oauthServer = new OAuthServer({
    authorizationUrl: new URL('http://localhost:3000/consent'),
    scopesSupported: ['mcp:tools'],
    grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
});
```

**Options**

- `model`: (optional) Storage backend. Default: `MemoryOAuthServerModel`.
- `authorizationUrl`: (required) Redirect URL for interactive authorization (consent). Required when `authorization_code` is enabled.
- `resourceServerUrl`: (optional) MCP resource server URL; used for resource validation and metadata when set.
- `scopesSupported`: (optional) Supported scopes; if the client omits `scope`, the server may default to these supported scopes.
- `accessTokenLifetime`: (optional) Access token lifetime in seconds. Default: `3600`.
- `refreshTokenLifetime`: (optional) Refresh token lifetime in seconds. Default: `1209600` (14 days).
- `clientSecretLifetime`: (optional) Client secret expiry in seconds, or `0` for no expiry. Default: `7776000` (90 days). Public clients (`token_endpoint_auth_method: 'none'`) have no secret.
- `authorizationCodeLifetime`: (optional) Authorization code lifetime in seconds. Default: `300`.
- `strictResource`: (optional) Validate the RFC 8707 `resource` parameter on authorize requests. Default: `true`.
- `modifyAuthorizationRedirectUrl`: (optional) Mutate the consent redirect URL (e.g. add client display hints as query parameters).
- `errorHandler`: (optional) Hook for logging or handling errors inside OAuth flows.
- `dynamicClientRegistration`: (optional) Enable RFC 7591 `/register`. Default: `true`. Construction fails if enabled and `model.registerClient` is missing.
- `grantTypes`: (optional) Enabled grants. Default: `['authorization_code', 'refresh_token']`. Add `'client_credentials'` and/or `DEVICE_AUTHORIZATION_GRANT_TYPE` as needed.
- `deviceAuthorizationUrl`: (optional) Page URL where the user enters the user code (RFC 8628). Required together with the device grant on `grantTypes`.
- `deviceAuthorizationLifetime`: (optional) Device code lifetime in seconds. Default: `900`.
- `devicePollIntervalSeconds`: (optional) Minimum poll interval returned to clients while authorization is pending. Default: `5`.

### OAuthServerModel

Storage interface for clients, codes, tokens, and (when enabled) device authorization records.

```ts
import type { OAuthServerModel, AccessToken } from 'mcp-oauth-server';

export class PostgresModel implements OAuthServerModel {
    async getClient(clientId: string) {
        return await this.db.loadClient(clientId);
    }

    async saveAccessToken(accessToken: AccessToken): Promise<void> {
        await this.db.saveAccessToken(accessToken);
    }

    async getAccessToken(token: string): Promise<AccessToken | undefined> {
        return await this.db.getAccessToken(token);
    }

    // Implement the remaining methods required for your enabled grant types:
    // authorization codes, refresh tokens, revocation, optional registration,
    // and device authorization helpers when using the device grant.
}
```

**Methods**

- `getClient`: (required) Resolve a registered client by id.
- `registerClient`: (required if `dynamicClientRegistration` is true) Persist dynamic registration.
- Authorization code grant: `saveAuthorizationCode`, `getAuthorizationCode`, `revokeAuthorizationCode` when `authorization_code` is enabled.
- Device grant: `saveDeviceAuthorization`, `getDeviceAuthorizationByDeviceCode`, `getDeviceAuthorizationByUserCode`, `deleteDeviceAuthorization` when the device grant is enabled.
- Tokens: `saveAccessToken`, `getAccessToken`, `revokeAccessToken`, `saveRefreshToken`, `getRefreshToken`, `revokeRefreshToken`.

### mcpAuthRouter

Express middleware that mounts OAuth authorization server routes and `.well-known` metadata.

```ts
import express from 'express';
import { mcpAuthRouter } from 'mcp-oauth-server';

const app = express();

app.use(
    mcpAuthRouter({
        provider: oauthServer,
        issuerUrl: new URL('http://localhost:3000'),
        baseUrl: new URL('http://localhost:3000/oauth'),
        resourceServerUrl: new URL('http://localhost:3000/mcp'),
        scopesSupported: ['mcp:tools'],
    }),
);
```

- **`issuerUrl`**: Authorization server issuer identifier (HTTPS in production; localhost is allowed for development).
- **`baseUrl`**: Optional AS URL base for OAuth endpoints (defaults to `issuerUrl`).
- **`resourceServerUrl`**: Resource server URL for protected-resource metadata.

Endpoints (paths are relative to where you mount the router and to `baseUrl` / issuer pathname):

- `/.well-known/oauth-authorization-server` and path-specific protected-resource metadata (RFC 8414 / RFC 9728)
- `/authorize` when `authorization_code` is in `grantTypes`
- `/token` — authorization code, refresh token, client credentials, and device code exchange (according to `grantTypes`)
- `/device` when the device grant is enabled and `deviceAuthorizationUrl` is set
- `/register` when `dynamicClientRegistration` is true
- `/revoke` — token revocation (RFC 7009)

Install at the application root (see [`src/router.ts`](src/router.ts)).

### authenticateHandler

Handles user consent completion after your consent UI (authorization code flow).

```ts
import { authenticateHandler } from 'mcp-oauth-server';

app.post(
    '/confirm',
    authenticateUserMiddleware(),
    authenticateHandler({
        provider: oauthServer,
        getUser: async (req) => {
            return req.session?.userId;
        },
        rateLimit: {
            windowMs: 15 * 60 * 1000,
            max: 100,
        },
    }),
);
```

**Options**

- `provider`: (required) `OAuthServer` instance.
- `getUser`: (required) Returns the authenticated user id (string or promise).
- `rateLimit`: (optional) `express-rate-limit` options, or `false` to disable.

### requireBearerAuth

Validates `Authorization: Bearer` tokens for protected routes (for example your MCP HTTP endpoint).

```ts
import { getOAuthProtectedResourceMetadataUrl, requireBearerAuth } from 'mcp-oauth-server';

const mcpUrl = new URL('http://localhost:3000/mcp');

app.post(
    '/mcp',
    requireBearerAuth({
        verifier: oauthServer,
        requiredScopes: ['mcp:tools'],
        resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpUrl),
    }),
    async (req, res) => {
        const clientId = req.auth!.clientId;
        const userId = req.auth!.userId;
        // Handle MCP request…
    },
);
```

See [`src/middleware/bearerAuth.ts`](src/middleware/bearerAuth.ts) for options.

After successful authentication, `req.auth` contains:

- `token`: Raw access token string
- `clientId`: OAuth client id
- `scopes`: Granted scopes
- `userId`: Present for user-centric grants; absent for pure client-credentials tokens
