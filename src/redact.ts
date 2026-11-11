import crypto from 'node:crypto';

export const REDACTED = '[redacted]';

/**
 * A short, stable stand-in for a high-entropy credential, for logs and error reports.
 *
 * Two log lines about the same token carry the same fingerprint, so they can still be
 * correlated, but the fingerprint cannot be used in place of the token. Only safe for values
 * with enough entropy that hashing guesses is hopeless - tokens, codes, PKCE verifiers. A
 * device `user_code` is short enough to enumerate, so it gets {@link REDACTED} instead.
 */
export function fingerprint(secret: string): string {
    return `sha256:${crypto.createHash('sha256').update(secret).digest('hex').slice(0, 12)}`;
}

/** A copy of a client that is safe to log: everything but the value of its secret. */
export function redactClient<T extends { client_secret?: string }>(client: T): T {
    return client.client_secret === undefined ? client : { ...client, client_secret: REDACTED };
}

const FINGERPRINTED_KEYS = ['authorizationCode', 'codeVerifier', 'refreshToken', 'deviceCode'] as const;

/**
 * Strips credentials from the context object handed to `errorHandler` and to debug logging.
 *
 * Error handlers forward what they are given to log aggregators and error trackers, which keep
 * it for a long time and are read by many people. A refresh token or client secret arriving
 * there is a leaked credential, and several of these errors fire while the credential is still
 * valid - a refresh rejected for a bad scope, a code exchange rejected for a bad verifier.
 */
export function redactErrorContext(params: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
    if (!params) {
        return params;
    }

    const redacted: Record<string, unknown> = { ...params };

    if (redacted.client && typeof redacted.client === 'object') {
        redacted.client = redactClient(redacted.client as { client_secret?: string });
    }
    for (const key of FINGERPRINTED_KEYS) {
        if (typeof redacted[key] === 'string') {
            redacted[key] = fingerprint(redacted[key]);
        }
    }
    if (typeof redacted.userCode === 'string') {
        redacted.userCode = REDACTED;
    }
    // revokeToken reports the revocation request, whose `token` is the credential.
    const request = redacted.request as { token?: unknown } | undefined;
    if (request && typeof request === 'object' && typeof request.token === 'string') {
        redacted.request = { ...request, token: fingerprint(request.token) };
    }

    return redacted;
}
