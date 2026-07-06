const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

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
