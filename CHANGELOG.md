# Changelog

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
