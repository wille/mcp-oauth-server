/**
 * Parses a space-delimited `scope` parameter (RFC 6749 §3.3) into a list of scope tokens.
 *
 * Returns `undefined` when the parameter is absent or contains no tokens, which is how the
 * rest of the library recognises "the client asked for nothing in particular" and falls back to
 * the server's default scopes. An empty array would mean something else: an explicit request
 * for no scopes at all.
 *
 * Splitting on any run of whitespace rather than a single space keeps a stray double space or
 * an empty `scope=` from producing an empty-string scope, which no server supports and which
 * would otherwise fail the whole request with `invalid_scope`.
 */
export function parseScope(scope: string | undefined): string[] | undefined {
    const scopes = scope?.split(/\s+/).filter(Boolean);
    return scopes?.length ? scopes : undefined;
}
