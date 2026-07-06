import express, { RequestHandler } from 'express';
import { clientRegistrationHandler, ClientRegistrationHandlerOptions } from './handlers/register.js';
import { tokenHandler, TokenHandlerOptions } from './handlers/token.js';
import { authorizationHandler, AuthorizationHandlerOptions } from './handlers/authorize.js';
import { revocationHandler, RevocationHandlerOptions } from './handlers/revoke.js';
import { deviceAuthorizationHandler, DeviceAuthorizationHandlerOptions } from './handlers/device.js';
import { metadataHandler } from './handlers/metadata.js';
import { OAuthServer } from './OAuthServer.js';
import { DEVICE_AUTHORIZATION_GRANT_TYPE } from './deviceFlow.js';
import { OAuthMetadata, OAuthProtectedResourceMetadata } from './schemas.js';

// Check for dev mode flag that allows HTTP issuer URLs (for development/testing only)
const allowInsecureIssuerUrl =
    process.env.MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL === 'true' || process.env.MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL === '1';
if (allowInsecureIssuerUrl) {
    // eslint-disable-next-line no-console
    console.warn('MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL is enabled - HTTP issuer URLs are allowed. Do not use in production.');
}

export type AuthRouterOptions = {
    /**
     * A provider implementing the actual authorization logic for this router.
     * The provider's `issuerUrl` is used as the issuer identifier in the advertised metadata.
     */
    provider: OAuthServer;

    /**
     * The base URL of the authorization server to use for the metadata endpoints.
     *
     * If not provided, the provider's issuer URL will be used as the base URL.
     */
    baseUrl?: URL;

    /**
     * An optional URL of a page containing human-readable information that developers might want or need to know when using the authorization server.
     */
    serviceDocumentationUrl?: URL;

    /**
     * The resource name to be displayed in protected resource metadata
     */
    resourceName?: string;

    /**
     * The URL of the protected resource (RS) whose metadata we advertise.
     * If not provided, falls back to `baseUrl` and then to the provider's `issuerUrl` (AS=RS).
     */
    resourceServerUrl?: URL;

    /**
     * Scopes supported by this authorization server (OAuth metadata and protected-resource metadata).
     * Falls back to {@link OAuthServer.scopesSupported} on the provider when omitted.
     */
    scopesSupported?: string[];
    // Individual options per route
    authorizationOptions?: Omit<AuthorizationHandlerOptions, 'provider'>;
    clientRegistrationOptions?: Omit<ClientRegistrationHandlerOptions, 'provider'>;
    revocationOptions?: Omit<RevocationHandlerOptions, 'provider'>;
    tokenOptions?: Omit<TokenHandlerOptions, 'provider'>;
    deviceAuthorizationOptions?: Omit<DeviceAuthorizationHandlerOptions, 'provider'>;
};

const checkIssuerUrl = (issuer: URL): void => {
    // Technically RFC 8414 does not permit a localhost HTTPS exemption, but this will be necessary for ease of testing
    if (issuer.protocol !== 'https:' && issuer.hostname !== 'localhost' && issuer.hostname !== '127.0.0.1' && !allowInsecureIssuerUrl) {
        throw new Error('Issuer URL must be HTTPS');
    }
    if (issuer.hash) {
        throw new Error(`Issuer URL must not have a fragment: ${issuer}`);
    }
    if (issuer.search) {
        throw new Error(`Issuer URL must not have a query string: ${issuer}`);
    }
};

export const createOAuthMetadata = (options: {
    provider: OAuthServer;
    baseUrl?: URL;
    serviceDocumentationUrl?: URL;
    scopesSupported?: string[];
}): OAuthMetadata => {
    const issuer = options.provider.issuerUrl;
    if (!issuer) {
        throw new Error('OAuthServer must be configured with issuerUrl to serve authorization server metadata');
    }
    const baseUrl = options.baseUrl || issuer;

    checkIssuerUrl(issuer);

    const basePath = baseUrl.pathname.endsWith('/') ? baseUrl.pathname.slice(0, -1) : baseUrl.pathname;

    const registration_endpoint = options.provider.dynamicClientRegistration ? new URL(`${basePath}/register`, baseUrl).href : undefined;
    const revocation_endpoint = new URL(`${basePath}/revoke`, baseUrl).href;

    const enableAuthorizationCodeGrant = options.provider.grantTypes.includes('authorization_code');

    const grant_types_supported = ['refresh_token'];
    if (enableAuthorizationCodeGrant) {
        grant_types_supported.unshift('authorization_code');
    }
    if (options.provider.grantTypes.includes('client_credentials')) {
        grant_types_supported.push('client_credentials');
    }
    if (options.provider.grantTypes.includes(DEVICE_AUTHORIZATION_GRANT_TYPE) && options.provider.deviceAuthorizationUrl) {
        grant_types_supported.push(DEVICE_AUTHORIZATION_GRANT_TYPE);
    }

    const metadata = {
        issuer: issuer.href,
        service_documentation: options.serviceDocumentationUrl?.href,

        authorization_endpoint: enableAuthorizationCodeGrant ? new URL(`${basePath}/authorize`, baseUrl).href : undefined,
        response_types_supported: enableAuthorizationCodeGrant ? ['code'] : [],
        code_challenge_methods_supported: ['S256'],

        token_endpoint: new URL(`${basePath}/token`, baseUrl).href,
        token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
        grant_types_supported,

        scopes_supported: options.scopesSupported,

        revocation_endpoint,
        revocation_endpoint_auth_methods_supported: revocation_endpoint ? ['client_secret_post'] : undefined,

        registration_endpoint,

        // RFC 9207: OAuthServer.authenticate() and the bundled handlers append `iss` to
        // every redirect back to the client's redirect_uri, so we can claim support.
        // SEP-2468 clients reject a callback that omits `iss` when support is advertised,
        // so custom consent flows that issue the callback redirect themselves must
        // append `iss` as well.
        authorization_response_iss_parameter_supported: true,

        device_authorization_endpoint:
            options.provider.grantTypes.includes(DEVICE_AUTHORIZATION_GRANT_TYPE) && options.provider.deviceAuthorizationUrl
                ? new URL(`${basePath}/device`, baseUrl).href
                : undefined,
    } as OAuthMetadata;

    return metadata;
};

/**
 * Installs standard MCP authorization server endpoints, including dynamic client registration and token revocation (if supported).
 * Also advertises standard authorization server metadata, for easier discovery of supported configurations by clients.
 * Note: if your MCP server is only a resource server and not an authorization server, use mcpAuthMetadataRouter instead.
 *
 * By default, rate limiting is applied to all endpoints to prevent abuse.
 *
 * This router MUST be installed at the application root, like so:
 *
 *  const app = express();
 *  app.use(mcpAuthRouter(...));
 */
export function mcpAuthRouter(options: AuthRouterOptions): RequestHandler {
    const oauthMetadata = createOAuthMetadata(options);

    const router = express.Router();

    if (options.provider.grantTypes.includes('authorization_code')) {
        router.use(
            new URL(oauthMetadata.authorization_endpoint).pathname,
            authorizationHandler({ provider: options.provider, ...options.authorizationOptions }),
        );
    }

    router.use(
        new URL(oauthMetadata.token_endpoint).pathname,
        tokenHandler({
            provider: options.provider,
            ...options.tokenOptions,
        }),
    );

    router.use(
        mcpAuthMetadataRouter({
            oauthMetadata,
            baseUrl: options.baseUrl,
            // Prefer explicit RS; otherwise fall back to AS baseUrl, then to issuer (back-compat)
            resourceServerUrl: options.resourceServerUrl ?? options.baseUrl ?? new URL(oauthMetadata.issuer),
            serviceDocumentationUrl: options.serviceDocumentationUrl,
            scopesSupported: options.scopesSupported ?? options.provider.scopesSupported,
            resourceName: options.resourceName,
        }),
    );

    if (oauthMetadata.device_authorization_endpoint) {
        router.use(
            new URL(oauthMetadata.device_authorization_endpoint).pathname,
            deviceAuthorizationHandler({ provider: options.provider, ...options.deviceAuthorizationOptions }),
        );
    }

    if (options.provider.dynamicClientRegistration && oauthMetadata.registration_endpoint) {
        router.use(
            new URL(oauthMetadata.registration_endpoint).pathname,
            clientRegistrationHandler({
                provider: options.provider,
                ...options.clientRegistrationOptions,
            }),
        );
    }

    if (oauthMetadata.revocation_endpoint) {
        router.use(
            new URL(oauthMetadata.revocation_endpoint).pathname,
            revocationHandler({ provider: options.provider, ...options.revocationOptions }),
        );
    }

    return router;
}

export type AuthMetadataOptions = {
    /**
     * OAuth Metadata as would be returned from the authorization server
     * this MCP server relies on
     */
    oauthMetadata: OAuthMetadata;

    /**
     * The base URL of the authorization server to use for the metadata endpoints.
     *
     * If not provided, the issuer URL will be used as the base URL.
     */
    baseUrl?: URL;

    /**
     * The url of the MCP server, for use in protected resource metadata
     */
    resourceServerUrl: URL;

    /**
     * The url for documentation for the MCP server
     */
    serviceDocumentationUrl?: URL;

    /**
     * An optional list of scopes supported by this MCP server
     */
    scopesSupported?: string[];

    /**
     * An optional resource name to display in resource metadata
     */
    resourceName?: string;
};

export function mcpAuthMetadataRouter(options: AuthMetadataOptions): express.Router {
    checkIssuerUrl(new URL(options.oauthMetadata.issuer));

    const router = express.Router();

    const protectedResourceMetadata: OAuthProtectedResourceMetadata = {
        resource: options.resourceServerUrl.href,

        authorization_servers: [options.oauthMetadata.issuer],

        scopes_supported: options.scopesSupported,
        resource_name: options.resourceName,
        resource_documentation: options.serviceDocumentationUrl?.href,
    };

    // Serve PRM at the path-specific URL per RFC 9728
    const rsPath = new URL(options.resourceServerUrl.href).pathname;
    router.use(`/.well-known/oauth-protected-resource${rsPath === '/' ? '' : rsPath}`, metadataHandler(protectedResourceMetadata));

    // Always add this for OAuth Authorization Server metadata per RFC 8414
    const asPath = new URL(options.baseUrl || options.oauthMetadata.issuer).pathname;
    router.use(`/.well-known/oauth-authorization-server${asPath === '/' ? '' : asPath}`, metadataHandler(options.oauthMetadata));

    return router;
}

/**
 * Helper function to construct the OAuth 2.0 Protected Resource Metadata URL
 * from a given server URL. This replaces the path with the standard metadata endpoint.
 *
 * @param serverUrl - The base URL of the protected resource server
 * @returns The URL for the OAuth protected resource metadata endpoint
 *
 * @example
 * getOAuthProtectedResourceMetadataUrl(new URL('https://api.example.com/mcp'))
 * // Returns: 'https://api.example.com/.well-known/oauth-protected-resource/mcp'
 */
export function getOAuthProtectedResourceMetadataUrl(serverUrl: URL): string {
    const u = new URL(serverUrl.href);
    const rsPath = u.pathname && u.pathname !== '/' ? u.pathname : '';
    return new URL(`/.well-known/oauth-protected-resource${rsPath}`, u).href;
}
