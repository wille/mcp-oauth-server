export { OAuthServer, SUPPORTED_GRANT_TYPES, DEFAULT_GRANT_TYPES, SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS } from './OAuthServer';
export type { OAuthServerOptions, OAuthGrantType } from './OAuthServer';
export type { OAuthServerModel } from './OAuthServerModel';
export type {
    AccessToken,
    RefreshToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthInfo,
    ClientIdMetadataDocument,
    DeviceAuthorization,
    DeviceAuthorizationEndpointResponse,
    DeviceAuthorizationStatus,
    GrantId,
} from './types';
export { DEVICE_AUTHORIZATION_GRANT_TYPE, generateDeviceUserCode, normalizeDeviceUserCode } from './deviceFlow';
// Handlers you mount yourself. The authorize, token, register, revoke and metadata handlers are
// mounted for you by mcpAuthRouter and stay internal.
export { authenticateHandler } from './handlers/authenticate';
export type { AuthenticationHandlerOptions } from './handlers/authenticate';
export { approveDeviceAuthorizationHandler } from './handlers/approveDeviceAuthorization';
export type { ApproveDeviceAuthorizationHandlerOptions } from './handlers/approveDeviceAuthorization';
export { denyDeviceAuthorizationHandler } from './handlers/denyDeviceAuthorization';
export type { DenyDeviceAuthorizationHandlerOptions } from './handlers/denyDeviceAuthorization';
export { deviceAuthorizationHandler } from './handlers/device';
export type { DeviceAuthorizationHandlerOptions } from './handlers/device';
export { MemoryOAuthServerModel } from './MemoryOAuthServerModel';
export { AuthorizationPendingError, SlowDownError, ExpiredTokenError, InvalidRequestError, OAuthError, ServerError } from './errors.js';

export { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter, mcpAuthMetadataRouter } from './router.js';
export type { AuthRouterOptions, AuthMetadataOptions } from './router.js';
export { requireBearerAuth } from './middleware/bearerAuth.js';
export type { BearerAuthMiddlewareOptions } from './middleware/bearerAuth.js';
export { checkResourceAllowed } from './resource-uri.js';
export { redirectUriMatches, isSecureRedirectUri } from './redirect-uri.js';
export { isClientIdMetadataDocumentUrl, ClientIdMetadataDocumentFetcher } from './cimd.js';
export type { ClientIdMetadataDocumentOptions } from './cimd.js';
export * from './schemas.js';
