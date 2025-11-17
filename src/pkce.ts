import { InvalidGrantError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import crypto from 'node:crypto';

export function validateChallenge(codeChallenge: string, codeVerifier: string) {
    const computedChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    if (computedChallenge !== codeChallenge) {
        throw new InvalidGrantError('code_verifier does not match the challenge');
    }
}
