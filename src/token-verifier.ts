import { AuthInfo } from './types.js';

/**
 * Slim implementation useful for token verification
 */
export interface OAuthTokenVerifier {
    /**
     * Verifies an access token and returns information about it.
     */
    verifyAccessToken(token: string): Promise<AuthInfo>;
}
