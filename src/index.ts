export { OAuthServer } from './OAuthServer';
export type { OAuthServerModel } from './OAuthServerModel';
export type {
    AccessToken,
    RefreshToken,
    AuthorizationCode,
    ClientIdMetadataDocument,
    DeviceAuthorization,
    DeviceAuthorizationEndpointResponse,
    DeviceAuthorizationStatus,
} from './types';
export { DEVICE_AUTHORIZATION_GRANT_TYPE, generateDeviceUserCode, normalizeDeviceUserCode } from './deviceFlow';
export { authenticateHandler } from './handlers/authenticate';
export { approveDeviceAuthorizationHandler } from './handlers/approveDeviceAuthorization';
export { denyDeviceAuthorizationHandler } from './handlers/denyDeviceAuthorization';
export { deviceAuthorizationHandler } from './handlers/device';
export { MemoryOAuthServerModel } from './MemoryOAuthServerModel';
export { AuthorizationPendingError, SlowDownError, ExpiredTokenError, InvalidRequestError, OAuthError, ServerError } from './errors.js';

export { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter } from './router.js';
export { requireBearerAuth } from './middleware/bearerAuth.js';
export { checkResourceAllowed } from './resource-uri.js';
export { redirectUriMatches, isSecureRedirectUri } from './redirect-uri.js';
export { isClientIdMetadataDocumentUrl, ClientIdMetadataDocumentFetcher } from './cimd.js';
export type { ClientIdMetadataDocumentOptions } from './cimd.js';
export * from './schemas.js';
