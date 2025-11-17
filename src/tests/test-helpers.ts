import crypto from 'node:crypto';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';

/**
 * Generate a PKCE code_verifier and code_challenge pair
 */
export function generatePKCEPair(): { codeVerifier: string; codeChallenge: string } {
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    return { codeVerifier, codeChallenge };
}

/**
 * Create a standard test client configuration
 */
export function createTestClient(overrides?: Partial<OAuthClientInformationFull>): OAuthClientInformationFull {
    return {
        client_id: 'test-client-id',
        client_id_issued_at: Math.floor(Date.now() / 1000),
        redirect_uris: ['http://localhost:3000/callback', 'http://localhost:3000/callback2'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
        ...overrides,
    };
}
