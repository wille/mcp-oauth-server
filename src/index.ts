export { OAuthServer } from './OAuthServer';
export type { OAuthServerModel } from './OAuthServerModel';
export type { AccessToken, RefreshToken, AuthorizationCode } from './types';
export { authenticateHandler } from './handlers/authenticate';
export { MemoryOAuthServerModel } from './MemoryOAuthServerModel';

export { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
export { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
export { checkResourceAllowed } from '@modelcontextprotocol/sdk/shared/auth-utils.js';

// Add the userId field to AuthInfo and return it in verifyAccessToken
// and so we can access it after requireBearerAuth
declare module '@modelcontextprotocol/sdk/server/auth/types.js' {
    interface AuthInfo {
        userId: string;
    }
}
