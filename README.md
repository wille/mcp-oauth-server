[![NPM package](https://img.shields.io/npm/v/mcp-oauth-server.svg?style=flat-square)](https://www.npmjs.com/package/mcp-oauth-server)
[![Build status](https://img.shields.io/github/actions/workflow/status/wille/mcp-oauth-server/commit.yml?style=flat-square)](https://github.com/wille/mcp-oauth-server/actions/workflows/commit.yml)
[![NPM downloads](https://img.shields.io/npm/dm/mcp-oauth-server.svg?style=flat-square)](https://www.npmjs.com/package/mcp-oauth-server)
[![License](https://img.shields.io/npm/l/mcp-oauth-server.svg?style=flat-square)](https://github.com/wille/mcp-oauth-server/blob/master/LICENSE)

# mcp-oauth-server

Self-hosted OAuth 2.1 Authorization Server for MCP servers, as Express middleware in TypeScript. Implements the [MCP Authorization Spec](https://modelcontextprotocol.io/specification/draft/basic/authorization) so you can protect your MCP server with OAuth without depending on a hosted auth vendor - and with no runtime dependency on the MCP SDK.

Originally forked from the (now sunset) OAuth 2.1 Authorization Server implementation in [@modelcontextprotocol/typescript-sdk](https://github.com/modelcontextprotocol/typescript-sdk).

## When to use this package

- You are building a **remote MCP server** and need an **OAuth authorization server** that MCP clients (Claude, ChatGPT, VS Code, ...) can register against and obtain tokens from - with your own login/consent screen and your own storage.
- You want the authorization server and the protected MCP server (resource server) in one Express app, or split across services sharing an `OAuthServerModel`.
- You need the client registration mechanisms MCP clients actually use: Client ID Metadata Documents and Dynamic Client Registration.

If you only need to **validate** tokens issued by an external identity provider, you don't need the full server - use [`requireBearerAuth`](#requirebearerauth) with a custom verifier.

## Table of Contents

- [When to use this package](#when-to-use-this-package)
- [Installation](#installation)
- [Features](#features)
- [OAuth client credentials](#oauth-client-credentials-machine-to-machine)
- [Device authorization (RFC 8628)](#device-authorization-rfc-8628)
- [Client ID Metadata Documents (CIMD)](#client-id-metadata-documents-cimd)
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

- **MCP Authorization Spec compliant**: Aligns with the [MCP Authorization Spec](https://modelcontextprotocol.io/specification/draft/basic/authorization)
    - [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) with mandatory PKCE (`S256` only, [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636))
    - [Client ID Metadata Documents](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00) - opt-in, see [CIMD](#client-id-metadata-documents-cimd)
    - Bearer token usage [(RFC 6750)](https://datatracker.ietf.org/doc/html/rfc6750) - `requireBearerAuth` with `WWW-Authenticate` challenges (`resource_metadata`, `scope`, `insufficient_scope`)
    - Resource Indicators [(RFC 8707)](https://datatracker.ietf.org/doc/html/rfc8707) with token audience validation
    - Dynamic Client Registration [(RFC 7591)](https://datatracker.ietf.org/doc/html/rfc7591) - deprecated by the MCP spec in favor of [CIMD](#client-id-metadata-documents-cimd), kept for backwards compatibility
    - Token Revocation [(RFC 7009)](https://datatracker.ietf.org/doc/html/rfc7009)
    - Authorization Server Metadata [(RFC 8414)](https://datatracker.ietf.org/doc/html/rfc8414)
    - Protected Resource Metadata [(RFC 9728)](https://datatracker.ietf.org/doc/html/rfc9728)
    - Authorization Server Issuer Identification [(RFC 9207)](https://datatracker.ietf.org/doc/html/rfc9207)
    - Loopback redirect URIs with any port for native apps [(RFC 8252 §7.3)](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3)
- **Grant types**: Configurable via `grantTypes` - `authorization_code`, `refresh_token`, [`client_credentials`](#oauth-client-credentials-machine-to-machine), and [device authorization](https://datatracker.ietf.org/doc/html/rfc8628) (`urn:ietf:params:oauth:grant-type:device_code`, RFC 8628)
- **Compatibility**: Works with MCP clients that omit a `resource` indicator [(RFC 8707)](https://datatracker.ietf.org/doc/html/rfc8707) or requested scopes when needed (`strictResource`)
- **Flexible storage**: In-memory model for development (`MemoryOAuthServerModel`) or your own `OAuthServerModel` for production

**Not supported:**

- Token introspection [(RFC 7662)](https://datatracker.ietf.org/doc/html/rfc7662) - validate access tokens via `OAuthServer.verifyAccessToken` (and `requireBearerAuth`) instead.
- `private_key_jwt` client authentication for CIMD clients - CIMD clients are treated as public clients (`token_endpoint_auth_method: 'none'`).
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) - RFC 8414 metadata satisfies the MCP spec's discovery requirement on its own.

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

Tokens minted for this grant typically have **no `userId`** on `AuthInfo` - authorize by `clientId` and scopes where appropriate.

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

3. Implement the device-related methods on `OAuthServerModel` (`saveDeviceAuthorization`, `getDeviceAuthorizationByDeviceCode`, `getDeviceAuthorizationByUserCode`, `deleteDeviceAuthorization`, `consumeApprovedDeviceAuthorization`, `resolvePendingDeviceAuthorization`) - see `MemoryOAuthServerModel` for a reference.

The auth router exposes **`POST /device`** (under your AS base path) when the device grant and `deviceAuthorizationUrl` are configured. Metadata lists `device_authorization_endpoint` accordingly.

**Approving or denying a login**

Wire **`approveDeviceAuthorizationHandler`** and **`denyDeviceAuthorizationHandler`** on routes you choose; they accept `user_code` (and resolve the authenticated user via `getUser`) so the user can approve or reject the device login out-of-band.

## Client ID Metadata Documents (CIMD)

[Client ID Metadata Documents](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00) let clients use an HTTPS URL as their `client_id`. The authorization server fetches a JSON metadata document from that URL (`client_id`, `client_name`, `redirect_uris`, ...) instead of requiring registration. The [draft MCP Authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration#client-id-metadata-documents) recommends CIMD and deprecates Dynamic Client Registration in its favor.

Support is **opt-in** because it makes the server issue outbound HTTPS requests to client-supplied URLs:

```ts
const oauthServer = new OAuthServer({
    // enable with defaults
    clientIdMetadataDocuments: true,

    // or configure it
    clientIdMetadataDocuments: {
        // Trust policy: reject metadata URLs outside your allowlist
        validateClientIdUrl: (url) => trustedDomains.includes(url.hostname),
        defaultCacheTtlSeconds: 300,
        maxCacheTtlSeconds: 3600,
        fetchTimeoutMs: 5000,
        fetch: myCustomFetch, // defaults to the Node built-in fetch
    },
    // ...
});
```

When enabled, the server metadata advertises `client_id_metadata_document_supported: true` and `OAuthServer.getClient` resolves URL-formatted client ids by fetching and validating the document: the document's `client_id` must equal the URL exactly, and `client_name` and at least one `redirect_uris` entry are required.

Fetched documents are cached through your `OAuthServerModel` (`saveClientIdMetadataDocument` / `getClientIdMetadataDocument`, implemented by `MemoryOAuthServerModel` out of the box) respecting `Cache-Control` headers, so multiple server instances sharing a model share the cache. Enabling CIMD on a custom model requires implementing both methods.

**Security notes**

- CIMD clients are public clients - documents demanding any `token_endpoint_auth_method` other than `none` are rejected (`private_key_jwt` is not supported).
- Non-HTTPS URLs, loopback/IP-literal hosts, redirects, and documents over 10 KB are always rejected. These checks do not cover DNS rebinding or internal hostnames - use `validateClientIdUrl` (or network egress filtering) if the server can reach internal services.
- CIMD cannot prevent localhost redirect URI impersonation by itself; consent screens should display the redirect URI hostname to the user.

## Quick Start

A minimal MCP authorization server protecting an MCP endpoint:

```ts
import express from 'express';
import { OAuthServer, mcpAuthRouter, requireBearerAuth, getOAuthProtectedResourceMetadataUrl } from 'mcp-oauth-server';

const mcpServerUrl = new URL('https://example.com/mcp');

const oauthServer = new OAuthServer({
    issuerUrl: new URL('https://example.com'),
    authorizationUrl: new URL('https://example.com/consent'), // your login/consent page
    scopesSupported: ['mcp:tools'],
    clientIdMetadataDocuments: true,
});

const app = express();

// OAuth endpoints: /.well-known metadata, /authorize, /token, /register, /revoke
app.use(mcpAuthRouter({ provider: oauthServer, resourceServerUrl: mcpServerUrl }));

// Your protected MCP endpoint
app.post(
    '/mcp',
    requireBearerAuth({
        verifier: oauthServer,
        requiredScopes: ['mcp:tools'],
        resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpServerUrl),
        resource: mcpServerUrl,
    }),
    (req, res) => {
        // req.auth is the validated token: clientId, userId, scopes
    },
);

app.listen(3000);
```

Your consent page completes the flow by calling [`authenticateHandler`](#authenticatehandler) with the authenticated user id.

A complete runnable example with a memory-backed authorization server and consent screen lives in [`./example`](example).

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
    issuerUrl: new URL('http://localhost:3000'),
    authorizationUrl: new URL('http://localhost:3000/consent'),
    scopesSupported: ['mcp:tools'],
    grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
});
```

**Options**

- `model`: (optional) Storage backend. Default: `MemoryOAuthServerModel`.
- `issuerUrl`: (required when using `mcpAuthRouter`) Authorization server issuer identifier (HTTPS in production; localhost is allowed for development). Used as the metadata `issuer` and appended as the RFC 9207 `iss` parameter on authorization responses.
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
- `dynamicClientRegistration`: (optional) Enable RFC 7591 `/register`. Default: `true`. Construction fails if enabled and `model.registerClient` is missing. Note: the MCP spec deprecates Dynamic Client Registration in favor of [CIMD](#client-id-metadata-documents-cimd); keep it enabled for backwards compatibility with clients that do not support CIMD.
- `clientIdMetadataDocuments`: (optional) Enable [Client ID Metadata Documents](#client-id-metadata-documents-cimd) - pass `true` or a `ClientIdMetadataDocumentOptions` object. Default: `false`.
- `allowInsecureRedirectUris`: (optional) Accept client redirect URIs that would carry the authorization response over cleartext `http`, which [OAuth 2.1 §2.3.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#section-2.3.1) forbids. Default: `false`. Loopback redirects (`http://127.0.0.1:1234/cb`, [RFC 8252 §7.3](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3)) and private-use URI schemes (`com.example.app:/cb`, `vscode://...`, [RFC 8252 §7.1](https://datatracker.ietf.org/doc/html/rfc8252#section-7.1)) are always allowed and unaffected by this setting, since neither crosses a network - so enabling it only permits `http` on a routable host, where anyone on the network path can read the authorization code out of the redirect. Development only. Enforced on dynamic client registration and CIMD documents; clients your own model returns are not inspected, so use the exported `isSecureRedirectUri` if you register clients yourself.
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
- Authorization code grant: `saveAuthorizationCode`, `consumeAuthorizationCode` when `authorization_code` is enabled.
- `consumeAuthorizationCode` and `consumeRefreshToken` (the latter required when `refresh_token` is enabled) must fetch **and** invalidate the record in a single atomic operation, matching on the client id, and return `undefined` if there is no match:

    ```sql
    DELETE FROM authorization_codes WHERE code = $1 AND client_id = $2 RETURNING *
    ```

    Atomicity is what makes the grant single-use (OAuth 2.1 §4.1.3): a read followed by a separate delete lets two concurrent requests each be issued their own tokens. Matching on the client id in the same statement means a request from the wrong client consumes nothing, so it cannot invalidate a grant another client is about to redeem.

- Device grant: `saveDeviceAuthorization`, `getDeviceAuthorizationByDeviceCode`, `getDeviceAuthorizationByUserCode`, `deleteDeviceAuthorization`, `consumeApprovedDeviceAuthorization`, `resolvePendingDeviceAuthorization` when the device grant is enabled. The last two carry the same atomicity requirement: a device code must yield tokens to only one poll, and a pending authorization must move to `approved` or `denied` exactly once.
- CIMD: `saveClientIdMetadataDocument`, `getClientIdMetadataDocument` when [`clientIdMetadataDocuments`](#client-id-metadata-documents-cimd) is enabled.
- Tokens: `saveAccessToken`, `getAccessToken`, `revokeAccessToken`, `saveRefreshToken`, `revokeRefreshToken`.
- `revokeAccessToken` and `revokeRefreshToken` take the requesting client's id and **must only revoke a token issued to that client** (`DELETE ... WHERE token = $1 AND client_id = $2 RETURNING *`). RFC 7009 §2.1 requires the revocation endpoint to verify ownership; letting the store decide keeps §2.2's "always answer 200" rule intact, so revocation cannot be used to probe for another client's tokens. Never throw when nothing matches - return the removed record, or `undefined`.
- `revokeGrant`: (required) Revoke every access and refresh token sharing a `grantId`. RFC 7009 §2.1 says revoking a refresh token SHOULD also invalidate access tokens from the same authorization grant; without this, a disconnected client keeps working until its access token expires. Needs a `grant_id` column populated from the `grantId` on saved codes, tokens and device authorizations - match on it exactly, so rows with no grant id are never swept up.

There is deliberately no `getAuthorizationCode` or `getRefreshToken` in the interface: the grant flows only ever consume, and a plain read next to a consume is the shape that reintroduces the race. `MemoryOAuthServerModel` still offers both for local introspection.

### mcpAuthRouter

Express middleware that mounts OAuth authorization server routes and `.well-known` metadata.

```ts
import express from 'express';
import { mcpAuthRouter } from 'mcp-oauth-server';

const app = express();

app.use(
    mcpAuthRouter({
        provider: oauthServer,
        baseUrl: new URL('http://localhost:3000/oauth'),
        resourceServerUrl: new URL('http://localhost:3000/mcp'),
        scopesSupported: ['mcp:tools'],
    }),
);
```

- **`provider`**: The `OAuthServer` instance. Its `issuerUrl` is used as the issuer identifier in the advertised metadata.
- **`baseUrl`**: Optional AS URL base for OAuth endpoints (defaults to the provider's `issuerUrl`).
- **`resourceServerUrl`**: Resource server URL for protected-resource metadata.

Endpoints (paths are relative to where you mount the router and to `baseUrl` / issuer pathname):

- `/.well-known/oauth-authorization-server` and path-specific protected-resource metadata (RFC 8414 / RFC 9728)
- `/authorize` when `authorization_code` is in `grantTypes`
- `/token` - authorization code, refresh token, client credentials, and device code exchange (according to `grantTypes`)
- `/device` when the device grant is enabled and `deviceAuthorizationUrl` is set
- `/register` when `dynamicClientRegistration` is true
- `/revoke` - token revocation (RFC 7009)

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
        resource: mcpUrl,
    }),
    async (req, res) => {
        const clientId = req.auth!.clientId;
        const userId = req.auth!.userId;
        // Handle MCP request…
    },
);
```

- `verifier`: Token verifier, typically the `OAuthServer` instance.
- `requiredScopes`: (optional) Scopes the token must include; missing scopes yield `403` with an `insufficient_scope` challenge.
- `resourceMetadataUrl`: (optional) Protected resource metadata URL advertised in `WWW-Authenticate` challenges (RFC 9728).
- `resource`: (optional) Canonical RFC 8707 resource identifier of this endpoint. When set, tokens must carry a matching resource (token audience validation); tokens without one are rejected with `401`. `OAuthServer.verifyAccessToken` already enforces this when `resourceServerUrl` is configured - set it here when using a custom verifier or protecting multiple resources.

See [`src/middleware/bearerAuth.ts`](src/middleware/bearerAuth.ts) for details.

After successful authentication, `req.auth` contains:

- `token`: Raw access token string
- `clientId`: OAuth client id
- `scopes`: Granted scopes
- `userId`: Present for user-centric grants; absent for pure client-credentials tokens
