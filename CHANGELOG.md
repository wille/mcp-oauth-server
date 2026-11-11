# Changelog

## Unreleased

### Security

- **Public clients could use the `client_credentials` grant.** A client registered with
  `token_endpoint_auth_method: 'none'` and `grant_types: ['client_credentials']` - or resolved from
  a Client ID Metadata Document listing that grant - holds no secret, so the token endpoint issued
  it an access token carrying every supported scope to anyone who knew its `client_id`. With
  dynamic client registration enabled that was anyone at all. RFC 6749 §4.4 restricts the grant to
  confidential clients: registration now answers `invalid_client_metadata` to that combination,
  and `exchangeClientCredentials` answers `unauthorized_client` to any client without a
  `client_secret`, wherever it came from.
- **`authenticateHandler` needs CSRF protection from your application, and the documentation did
  not say so.** A POST to it is the user's consent, and nothing in the request proves the user saw
  a consent screen. The handler's documentation and the README now carry the same warning the
  device approval handler already had, with an example. No code changed: if your consent route has
  no CSRF check and your session cookie is not `SameSite=Lax` or `Strict`, add one.
- **`errorHandler` and debug logging were given live credentials.** The context passed to
  `errorHandler` included the full client record with its `client_secret`, and the raw
  authorization code, PKCE verifier, refresh token, device code or token being revoked. An
  application forwarding that to a log aggregator or error tracker was storing usable credentials
  there - and several of these errors fire while the credential is still valid. Secrets and device
  user codes are now `[redacted]`, and tokens and codes are replaced by a `sha256:` fingerprint
  that still lets you correlate events. `DEBUG=oauth:*` output is redacted the same way. If your
  handler read a token or secret from this context, it no longer can.

### Fixed

- `clientSecretLifetime: 0` is documented as "never expire" but was read with `||`, so it silently
  became the 90-day default. It now yields `client_secret_expires_at: 0`, as RFC 7591 §3.2.1
  specifies for a secret that does not expire.
- The successful authorization redirect replaced the query string of the client's `redirect_uri`
  instead of adding to it, so a client registered with `https://app.example/cb?tenant=acme` got
  its callback without `tenant`. RFC 6749 §3.1.2 requires the query to be retained; the error
  redirect already did.
- An authorization request without a `scope` parameter was meant to default to every supported
  scope, as `scopesSupported` documents, but the authorize and consent handlers passed an empty
  list rather than "not specified". The resulting access token had no scopes at all and failed
  any `requireBearerAuth({ requiredScopes })` check with 403. Clients that omit `scope` now get
  the default, and the consent URL carries it so your consent screen can show it.
- `scope` is split on any run of whitespace. An empty `scope=` or a doubled space used to produce
  an empty-string scope and fail the request with `invalid_scope`.
- `strictResource: false` was not honoured by the refresh token grant. A client that omitted
  `resource` could redeem its authorization code but then got `invalid_target` on its first
  refresh. The grant now requires `resource` only under `strictResource`, like the code exchange;
  when it is sent it must still match, and the new tokens stay bound to the original resource.
- A refresh request rejected for its own parameters (`invalid_scope`, `invalid_target`) no longer
  costs the client its refresh token. The token had already been consumed by the time those
  checks ran, so a retry with the corrected request failed with `invalid_grant` and the user had
  to authorize again. The token is now put back through `saveRefreshToken` - see the note on that
  method if your model keeps consumed rows instead of deleting them.
- A device following the advertised polling interval was rate limited out of its own flow. The
  token endpoint allowed 50 requests per 15 minutes per IP, and a device polling every 5 seconds
  sends 180 in that time, so it started receiving 429 about four minutes in. Device polls are now
  counted by their own limiter, sized from `devicePollIntervalSeconds` (360 per 15 minutes at the
  default), and no longer count against the general token limit. Tune or disable it with the new
  `tokenOptions.devicePollRateLimit`; `rateLimit: false` still disables both.
- `error_description` for a malformed request was the validator's raw output: a multi-line JSON
  array of issues, which is unreadable once percent-encoded into an authorization error redirect
  and contains characters RFC 6749 §5.2 does not permit there. It is now one line naming each
  offending parameter, for example `response_type: Invalid input: expected 'code'`.
- `OAuthServer.verifyAccessToken` rejected a token whose scope had been removed from
  `scopesSupported`, or whose resource no longer matched `resourceServerUrl`, with `invalid_scope`
  / `invalid_target`. `requireBearerAuth` relayed those as a bare 400, which gives a client no
  reason to re-authorize. Both are now `invalid_token`: 401 with a `WWW-Authenticate` challenge.
- `authenticateHandler` and `approveDeviceAuthorizationHandler` answered 500 `server_error` when
  `getUser` returned no user. They now answer 401 `access_denied`.
- `requireBearerAuth` escapes quotes and backslashes in the `WWW-Authenticate` parameters, so an
  error message from a custom verifier cannot break out of its quoted value.
- A redirect URI containing a fragment is rejected at dynamic registration (`invalid_redirect_uri`)
  and in Client ID Metadata Documents (`invalid_client`), as RFC 6749 §3.1.2 requires.
- `code_challenge` and `code_verifier` are checked against the formats RFC 7636 defines: a
  43-character base64url challenge, and a verifier of 43 to 128 unreserved characters. A malformed
  challenge is now refused at the authorization endpoint instead of producing a code that could
  never be redeemed, and a client using a too-short verifier is told so. Conforming clients are
  unaffected.
- The dynamic registration response states `token_endpoint_auth_method: 'client_secret_post'` when
  the client did not ask for a method. Omitting it means `client_secret_basic` under RFC 7591,
  which this server does not accept.
- A device poll could undo the user's answer. Each pending poll stored its timestamp by saving
  back the whole device authorization it had read at the start of the request, so with any model
  that returns copies - every database - a poll overlapping the approval wrote `status: 'pending'`
  over it and the device never got its tokens; a denial could be undone the same way. Poll
  bookkeeping now goes through a new model method, `recordDeviceAuthorizationPoll`, which updates
  only the polling fields and only while the authorization is pending. **Custom models supporting
  the device grant should implement it** - it is optional so existing models keep working, but
  they keep the race until they do. `MemoryOAuthServerModel` implements it.

## 1.0.1

### Added

- `createOAuthMetadata` is exported, so a server can pass its authorization server metadata to
  `mcpAuthMetadataRouter` and serve a protected resource document for a second path (for
  example the root and `/mcp`) next to the one `mcpAuthRouter` mounts.

### Fixed

- `createOAuthMetadata` (and therefore `mcpAuthRouter`) now falls back to the provider's
  `scopesSupported` for `scopes_supported`, the way the protected resource metadata already did.
  A server that configured scopes only on `OAuthServer` advertised them in the protected resource
  document but not in the authorization server document, so clients reading the latter (Codex,
  Hermes Agent) saw no scopes.

## 1.0.0

First stable release. It carries security fixes and a reworked `OAuthServerModel` contract, so
**every deployment with a custom model needs the changes in [Migrating from 0.0.x](#migrating-from-00x)**.
Missing methods throw at construction with the method name in the message, so an incomplete model
fails on boot rather than silently losing a protection.

### Security

- **Consent could be granted by a cross-site GET.** `authenticateHandler` accepted `GET`, so it
  could be driven by a top-level navigation, which `SameSite=Lax` cookies are still sent on. An
  attacker who registered their own client could obtain an authorization code for a logged-in
  victim without any interaction; PKCE, `state` and `iss` offer nothing when the attacker is the
  client. The handler is now `POST`-only.
- **Grants were not atomically single-use.** Authorization codes, refresh tokens and device
  authorizations were read, validated, and only then invalidated. Concurrent requests presenting
  the same grant could each be issued their own tokens - five concurrent `/token` requests turned
  one authorization code into five distinct access tokens as soon as the model performed any real
  I/O between the read and the delete. The in-memory model happened to be safe because it never
  yields to the event loop, so the default looked correct while every database-backed model was
  exposed. Consumption is now one atomic, client-scoped operation.
- **Revocation ignored who owned the token.** Any client could revoke any token whose value it
  knew (RFC 7009 §2.1 requires the server to verify the token was issued to the requesting
  client). Revocation is now scoped to the authenticated client, inside the store, so the endpoint
  still answers `200` either way and cannot be used to probe for another client's tokens.
- **`token_type_hint` was treated as authoritative.** A refresh token submitted with
  `token_type_hint=access_token` was not found and stayed usable. RFC 7009 §2.1 requires the
  search to extend across all supported token types.
- **Revoking a refresh token left its access tokens alive** for up to `accessTokenLifetime`, an
  hour by default, so disconnecting a client did not end its access (RFC 7009 §2.1). Tokens now
  carry a `grantId` and revocation cascades across the grant.
- **Redirect URIs could be cleartext `http`.** A client could register
  `http://evil.example.com/cb` and have authorization codes delivered in the clear. TLS is now
  required, with the RFC 8252 exceptions for loopback addresses (§7.3) and private-use URI schemes
  (§7.1). `allowInsecureRedirectUris` opts out for development.
- **`policy_uri` accepted `javascript:`** while its siblings did not, so a consent screen rendering
  it as a link gave an attacker script execution on the authorization server's origin. Seven
  URL-valued fields across the metadata schemas had the same gap - five used `z.string().url()`,
  which validates syntax and accepts `javascript:` without complaint.
- **Device approval accepted `user_code` from the query string**, putting a credential into access
  logs, `Referer` headers and browser history. Both approval handlers now read the body only.
- **Client secrets were compared with `!==`**, which returns on the first differing byte. Now
  hashed and compared with `crypto.timingSafeEqual`.
- **A CIMD document was buffered in full before its size was checked.** An 8 MB response was held
  in memory before being rejected against a 10 KB limit; the `content-length` pre-check does not
  see a chunked response. The body is now read incrementally and abandoned once it passes the cap.
- **Device user codes were drawn with modulo bias.** `B`, `C`, `D` and `F` appeared 11% more often
  than the other characters. Now drawn with `crypto.randomInt`.

### Fixed

- Refresh tokens are no longer issued when the grant is disabled on the server or the client is not
  registered for it, and `grant_types_supported` no longer advertises `refresh_token`
  unconditionally. `exchangeRefreshToken` now checks the client's registered grants, as the other
  three grants already did.
- The token endpoint checks server grant support before client grant support, so a grant the server
  does not offer always answers `unsupported_grant_type` rather than `unauthorized_client`. The
  handler previously had no server-side check of its own, relying entirely on the provider.
- Registration rejects an empty `redirect_uris` for clients requesting the authorization code
  grant, which previously registered successfully and then failed every authorization attempt.
- `HEAD` is accepted wherever `GET` is (RFC 9110 §9.3.2), so the discovery endpoints no longer
  answer `405` to health checks and cache validators. `OPTIONS` still does; mount `cors()` ahead of
  the router if you need preflight.
- Authorization codes and tokens are encoded `base64url` instead of `base64`, so nothing needs
  escaping when a code travels as a query parameter.
- `package.json` declares `types`, so type declarations resolve under `node10` module resolution
  and for CommonJS `require` consumers, not only under `bundler`/`node16`/`nodenext`.

### Removed

- `OAuthServerModel.generateToken` - it was declared but never called, so a model implementing it
  was silently ignored.
- `OAuthServerModel.getAuthorizationCode` and `getRefreshToken` - see the migration notes.
- The unused `pkce-challenge` dependency. PKCE is verified with `node:crypto`.

### Not supported

- `client_secret_basic`. OAuth 2.1 §2.4.1 requires `client_secret_post` and makes Basic optional -
  the reverse of RFC 6749 §2.3.1 - and the MCP Authorization spec says nothing about client
  authentication. Registration rejects any `token_endpoint_auth_method` other than
  `client_secret_post` and `none`.
- Revoking the token family when a spent authorization code or refresh token is replayed
  (RFC 6749 §4.1.2, OAuth 2.1 §6.1). Atomic consumption denies the replay, but detecting one
  requires retaining spent records rather than deleting them.

---

## Migrating from 0.0.x

Nothing changes for callers of `mcpAuthRouter`, `requireBearerAuth` or the bundled handlers other
than `authenticateHandler` becoming `POST`-only. The work is in custom `OAuthServerModel`
implementations. `MemoryOAuthServerModel` already does all of this.

### 1. Add a `grant_id` column

Authorization codes, access tokens, refresh tokens and device authorizations now carry an optional
`grantId` identifying the authorization they descend from. Persist and return it. Rows written
before the upgrade will not have one, and the library treats its absence as "no grant to cascade
to", so existing tokens keep working.

### 2. Replace reads-then-writes with atomic consumption

`getAuthorizationCode` and `getRefreshToken` are gone from the interface. The flows only ever
consume, and a plain read next to a consume is the shape that allowed the same grant to be redeemed
twice. Each of these must fetch **and** invalidate in a single atomic operation, matching on the
client id, returning `undefined` when nothing matches:

```ts
// consumeAuthorizationCode(code, clientId)
DELETE FROM authorization_codes WHERE code = $1 AND client_id = $2 RETURNING *

// consumeRefreshToken(token, clientId)
DELETE FROM refresh_tokens WHERE token = $1 AND client_id = $2 RETURNING *

// consumeApprovedDeviceAuthorization(deviceCode, clientId)
DELETE FROM device_authorizations
 WHERE device_code = $1 AND client_id = $2 AND status = 'approved' RETURNING *

// resolvePendingDeviceAuthorization(userCode, status, userId)
UPDATE device_authorizations SET status = $2, user_id = $3
 WHERE user_code = $1 AND status = 'pending' RETURNING *
```

Two properties are load-bearing, and one statement gives you both:

- **Atomic.** A read followed by a separate delete lets two concurrent requests both observe a
  valid grant and each be issued tokens. A single statement the store executes atomically cannot.
- **Scoped to the client.** Matching on `client_id` inside the same statement means a request from
  the wrong client consumes nothing, so it cannot invalidate a grant another client is about to
  redeem.

`status = 'approved'` on the device consume is not optional either: devices poll the token endpoint
while the user has not answered yet, and deleting a pending authorization abandons a flow still in
progress.

If you keep spent records for auditing, use
`UPDATE ... SET consumed_at = now() WHERE ... AND consumed_at IS NULL RETURNING *` instead of
`DELETE`.

### 3. Scope revocation to the client, and return what you removed

`revokeAccessToken` and `revokeRefreshToken` take the requesting client's id and return the record
they removed, or `undefined`:

```ts
DELETE FROM access_tokens WHERE token = $1 AND client_id = $2 RETURNING *
```

The library needs the returned record's `grantId` to cascade the revocation. Do not throw when
nothing matches - the endpoint must answer `200` regardless, so that it cannot be used to discover
whether someone else's token exists.

### 4. Add `revokeGrant`

```ts
// revokeGrant(grantId)
DELETE FROM access_tokens  WHERE grant_id = $1;
DELETE FROM refresh_tokens WHERE grant_id = $1;
```

Match on `grant_id` exactly: rows with a null or empty grant id belong to no known authorization
and must never be swept up by this call.

### 5. Check the rest

- `authenticateHandler` is `POST`-only. If you mounted it with `app.use`, switch to `app.post`, and
  make sure your consent page submits rather than links.
- The approval handlers read `user_code` from the request body only. A verification page passing it
  as a query parameter needs to submit it as a form field.
- Mount your own CSRF middleware on the approval route. It is a state change carried out under
  whatever session `getUser` reads, and only your application can mint and check its own tokens.
- Clients registered with `http://` redirect URIs on routable hosts will be refused. Loopback and
  private-use schemes are unaffected. Set `allowInsecureRedirectUris` if you need the old behaviour
  in development.
- Clients registered with `token_endpoint_auth_method: 'client_secret_basic'` will be refused; use
  `client_secret_post` or `none`.
- Clients whose `grant_types` omit `refresh_token` no longer receive one. They could never have
  redeemed it, so nothing that worked stops working.
