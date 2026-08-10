const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Whether a redirect URI satisfies the transport security requirement for redirect URIs in
 * OAuth 2.1 (§2.3.1), which requires TLS so that an authorization code cannot be read off
 * the wire on its way back to the client.
 *
 * Two kinds of URI are accepted without TLS, both from RFC 8252, because neither crosses a
 * network and neither can present a certificate:
 *
 * - **Loopback** (§7.3), e.g. `http://127.0.0.1:49152/callback`. A native app receives the
 *   redirect on a listener it opened on the local machine.
 * - **Private-use URI schemes** (§7.1), e.g. `com.example.app:/callback` or `vscode://...`.
 *   The operating system hands the redirect to the registered app directly.
 *
 * So the rule reduces to: `http:` is only allowed on a loopback host, and every other
 * scheme is fine. `javascript:`, `data:` and `vbscript:` are rejected earlier, by
 * {@link SafeUrlSchema} where redirect URIs are parsed.
 *
 * Note RFC 8252 §8.3 discourages `localhost` in favour of the IP literals, since the name
 * can resolve to something other than the loopback interface. It is accepted here because
 * clients use it heavily, and because {@link redirectUriMatches} already treats it as
 * loopback.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
 * @see https://datatracker.ietf.org/doc/html/rfc8252#section-7.1
 */
export function isSecureRedirectUri(uri: string): boolean {
    let url: URL;
    try {
        url = new URL(uri);
    } catch {
        return false;
    }

    if (url.protocol !== 'http:') {
        return true;
    }

    return LOOPBACK_HOSTS.has(url.hostname);
}

/**
 * Validates a requested redirect_uri against a registered one.
 *
 * Per RFC 8252 §7.3 (OAuth 2.0 for Native Apps), authorization servers MUST
 * allow any port for loopback redirect URIs (localhost, 127.0.0.1, [::1]) to
 * accommodate native clients that obtain an ephemeral port from the OS. For
 * non-loopback URIs, exact match is required.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
 */
export function redirectUriMatches(requested: string, registered: string): boolean {
    if (requested === registered) {
        return true;
    }
    let req: URL, reg: URL;
    try {
        req = new URL(requested);
        reg = new URL(registered);
    } catch {
        return false;
    }
    // Port relaxation only applies when both URIs target a loopback host.
    if (!LOOPBACK_HOSTS.has(req.hostname) || !LOOPBACK_HOSTS.has(reg.hostname)) {
        return false;
    }
    // RFC 8252 relaxes the port only — scheme, host, path, and query must
    // still match exactly. Note: hostname must match exactly too (the RFC
    // does not allow localhost↔127.0.0.1 cross-matching).
    return req.protocol === reg.protocol && req.hostname === reg.hostname && req.pathname === reg.pathname && req.search === reg.search;
}
