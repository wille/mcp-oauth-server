import { InvalidGrantError } from './errors.js';
import crypto from 'node:crypto';
import * as z from 'zod/v4';

/**
 * RFC 7636 §4.2: an S256 code_challenge is BASE64URL(SHA256(code_verifier)) - 32 bytes, which
 * is always exactly 43 base64url characters with no padding.
 *
 * Anything else can never match a verifier, so accepting it only postpones the failure to the
 * token endpoint, after the user has been through the consent screen.
 */
export const CodeChallengeSchema = z
    .string()
    .regex(/^[A-Za-z0-9_-]{43}$/, { message: 'code_challenge must be a 43-character base64url-encoded SHA-256 digest' });

/**
 * RFC 7636 §4.1: a code_verifier is 43 to 128 characters from the unreserved set.
 *
 * The lower bound is the security property: PKCE protects a code only as far as the verifier
 * is unguessable, and a client sending a short one has none of that protection.
 */
export const CodeVerifierSchema = z
    .string()
    .regex(/^[A-Za-z0-9\-._~]{43,128}$/, { message: 'code_verifier must be 43 to 128 characters from A-Z, a-z, 0-9, "-", ".", "_", "~"' });

export function validateChallenge(codeChallenge: string, codeVerifier: string) {
    const computedChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    if (computedChallenge !== codeChallenge) {
        throw new InvalidGrantError('code_verifier does not match the challenge');
    }
}
