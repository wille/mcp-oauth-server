[![NPM package](https://img.shields.io/npm/v/mcp-oauth-server.svg?style=flat-square)](https://www.npmjs.com/package/mcp-oauth-server)

# mcp-oauth-server

OAuth 2.1 Authorization Server implementation built to support the [MCP Authorization Spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) through [@modelcontextprotocol/typescript-sdk](https://github.com/modelcontextprotocol/typescript-sdk).

Based on the MCP SDK's partial OAuth 2.1 Authorization Server implementation.

## Table of Contents

- [Installation](#installation)
- [Requirements](#requirements)
- [Features](#features)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
  - [OAuthServer](#oauthserver)
  - [mcpAuthRouter](#mcpauthrouter)
  - [authenticateHandler](#authenticatehandler)
  - [requireBearerAuth](#requirebearerauth)
- [Demo](#demo)
- [Limitations](#limitations)

## Installation

```bash
npm install mcp-oauth-server@latest --save-exact
```

## Features

- **MCP Authorization Spec Compliant**: Fully compliant with the [MCP Authorization Spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
    - [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
    - Dynamic Client Registration [(RFC 7591)](https://datatracker.ietf.org/doc/html/rfc7591)
    - Authorization Server Metadata [(RFC 8414)](https://datatracker.ietf.org/doc/html/rfc8414)
    - Protected Resource Metadata [(RFC 9728)](https://datatracker.ietf.org/doc/html/rfc9728)
- **SDK Integration**: Implements `OAuthServerProvider` from [@modelcontextprotocol/typescript-sdk](https://github.com/modelcontextprotocol/typescript-sdk)
- **Compatibility**: Supports MCP clients not fully compliant with the MCP Authorization Spec, such as clients that don't provide a `resource` indicator (RFC 8707) or any requested scopes
- **Flexible**: Works with in-memory storage (for development) or custom storage backends (for production)

## Quick Start

A complete working example of an MCP OAuth flow with a memory-backed OAuth 2.1 Authorization Server can be found in the [`./example`](example) folder.

**Run the demo:**

1. Start the server:
   ```bash
   pnpm example:server
   ```

2. In another terminal, authenticate with the server:
   ```bash
   pnpm example:client
   ```

The example demonstrates:
- Setting up an OAuth server with in-memory storage in front of a MCP server
- Creating a consent screen
- Handling authorization confirmation


## API Reference

### OAuthServer

An OAuth 2.1 Server instance that implements the OAuthServerProvider to be used with `mcpAuthRouter` from the [@modelcontextprotocol/typescript-sdk](https://github.com/modelcontextprotocol/typescript-sdk)

```ts
import { OAuthServer } from 'mcp-oauth-server';

const oauthServer = new OAuthServer({
    authorizationUrl: new URL('http://localhost:3000/consent'),
    strictResourceUrl: new URL('http://localhost:3000/mcp'),
    scopesSupported: ['mcp:tools'],
})
```

**Config options:**

- `model`: (optional) The storage model to use for the OAuth server. Default: `MemoryOAuthServerModel` (in-memory, suitable for development). For production, implement your own `OAuthServerModel` to use a database.
- `authorizationUrl`: (required) The URL to redirect the user to for authorization. This may be a consent screen hosted on the Authorization Server or a custom consent screen hosted on another frontend, like your web application.
- `scopesSupported`: (optional) Array of scopes supported by this OAuth server. If the client does not include any scopes in the request, the server will default to all the supported scopes. Some MCP clients do not follow the spec and do not include any scopes in the request.
- `accessTokenLifetime`: (optional) The lifetime of the access token in seconds. Default: `3600` (1 hour)
- `refreshTokenLifetime`: (optional) The lifetime of the refresh token in seconds. Default: `1209600` (2 weeks)
- `clientSecretLifetime`: (optional) The number of seconds after which to expire issued client secrets, or `0` to prevent expiration of client secrets (not recommended). Default: `7776000` (3 months). Public clients (clients registered with `token_endpoint_auth_method = 'none'`) do not have a client secret and live forever.
- `authorizationCodeLifetime`: (optional) The lifetime of the authorization code in seconds. Default: `300` (5 minutes)
- `strictResourceUrl`: (optional) The resource indicator (RFC 8707) that must be used for all requests. This should be set to your MCP server URL. Leaving this unset will allow better compatibility with MCP clients that do not follow the spec and do not include a resource indicator in the request.
- `modifyAuthorizationRedirectUrl`: (optional) A function to modify the authorization redirect URL. This can be used to add metadata to the authorization redirect URL, like the client name, client URI, or logo URI, which can then be displayed on your consent screen.
- `errorHandler`: (optional) A function to handle errors. This can be used to log errors occuring in the OAuth flow.

### OAuthServerModel

An interface for the storage model to use for the OAuth server. This is used to store the OAuth server's data, such as clients, tokens, and authorization codes.

```ts
import { OAuthServerModel } from 'mcp-oauth-server';

export class PostgresModel implements OAuthServerModel {
    async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
        const client = await this.db.query('SELECT * FROM clients WHERE client_id = $1', [clientId]);
        return client;
    }

    async registerClient(client: OAuthClientInformationFull): Promise<OAuthClientInformationFull> {
        // Modify or omit fields from the client metadata here if needed
        return client;
    }

    async getAccessToken(token: string): Promise<AccessToken | undefined> {
        const accessToken = await this.db.query('SELECT * FROM access_tokens WHERE token = $1', [token]);
        return accessToken;
    }

    async saveAccessToken(accessToken: AccessToken): Promise<void> {
        await this.db.query('INSERT INTO access_tokens (token, client_id, expires_at, scopes, resource) VALUES ($1, $2, $3, $4, $5)', [accessToken.token, accessToken.client_id, accessToken.expires_at, accessToken.scopes, accessToken.resource]);
    }
    
    /* ... */
}
```

**Config options:**

- `getClient`: (required) Get a client by its client ID.
- `registerClient`: (required) Register a new client and return any modifications to the client metadata.
- `getAccessToken`: (required) Get an access token by its token.
- `saveAccessToken`: (required) Save an access token.
- `revokeAccessToken`: (required) Revoke an access token.
- `getRefreshToken`: (required) Get a refresh token by its token.
- `saveRefreshToken`: (required) Save a refresh token.
- `revokeRefreshToken`: (required) Revoke a refresh token.
- `saveAuthorizationCode`: (required) Save an authorization code.
- `getAuthorizationCode`: (required) Get an authorization code by its code.
- `revokeAuthorizationCode`: (required) Revoke an authorization code.


### mcpAuthRouter

Express middleware that sets up all OAuth 2.1 Authorization Server endpoints (authorization, token, registration, metadata, etc.).

```ts
import express from 'express';
import { mcpAuthRouter } from 'mcp-oauth-server';

const app = express();
app.use(mcpAuthRouter({
    provider: oauthServer,
    issuerUrl: new URL('http://localhost:3000/'),
    resourceServerUrl: mcpServerUrl,
    scopesSupported: ['mcp:tools'],
}));
```

See [router.ts](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/src/server/auth/router.ts) for the full options.



### authenticateHandler

Express middleware that handles the authorization confirmation endpoint. This is called after the user grants consent on your consent screen.

```ts
import { authenticateHandler } from 'mcp-oauth-server';

app.post('/confirm', authenticateHandler({
    provider: oauthServer,
    getUser: (req) => {
        // Extract user ID from your authenticated session
        // or from the request body if you handle auth in the consent form
        return req.body.user_id || req.authenticatedUser?.id;
    },
    rateLimit: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // 100 requests per windowMs
    },
}));
```

**Config options:**

- `provider`: (required) The OAuthServer instance to use for authentication
- `getUser`: (required) A function to extract the authenticated user ID from the request. Your own authentication logic should either be done here or in a middleware before this one
- `rateLimit`: (optional) The rate limiting configuration for the authorization endpoint. Set to `false` to disable rate limiting for this endpoint

### requireBearerAuth

Express middleware that validates Bearer tokens and authenticates requests to protected resources (like your MCP server endpoint).

```ts
import { requireBearerAuth } from 'mcp-oauth-server';

app.post('/mcp', 
    requireBearerAuth({
        verifier: oauthServer,
        requiredScopes: ['mcp:tools'],
    }),
    async (req, res) => {
        // Access authenticated user ID
        const userId = req.auth.userId;
        console.log('Authenticated user:', userId);
        
        // Set up MCP Server...
    }
);
```

See [bearerAuth.ts](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/src/server/auth/middleware/bearerAuth.ts) for the full options.

After authentication, the request will have `req.auth` with:
- `userId`: The user ID associated with the token
- `token`: The access token used
- `scopes`: The scopes granted to the token



## Limitations

> [!WARNING]
> 
> You currently cannot run the Authorization Server (`mcpAuthRouter`) on a path other than root `/` path. See [modelcontextprotocol/typescript-sdk#1095](https://github.com/modelcontextprotocol/typescript-sdk/pull/1095)
> - There is no support for the [OAuth 2.1 client_credentials grant type](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#section-4.4.3), but this should not be a problem as most MCP clients use the `authorization_code` grant type. See [modelcontextprotocol/typescript-sdk#899](https://github.com/modelcontextprotocol/typescript-sdk/issues/899)


> [!NOTE]
> 
> - **Separate Servers**: You can run the OAuth Server (Authorization Server) on a different server from the MCP Server (Resource Server) as long as they share the same underlying model/storage backend
