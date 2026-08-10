import { AuthorizationParams } from './types.js';
import { OAuthRegisteredClientsStore } from './clients.js';
import {
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthClientMetadataSchema,
    OAuthTokenRevocationRequest,
    OAuthTokens,
} from './schemas.js';
import { Response } from 'express';
import { AuthInfo } from './types.js';
import { checkResourceAllowed, resourceUrlFromServerUrl } from './resource-uri.js';
import { redirectUriMatches } from './redirect-uri.js';
import {
    CustomOAuthError,
    AccessDeniedError,
    AuthorizationPendingError,
    ExpiredTokenError,
    InvalidClientError,
    InvalidGrantError,
    InvalidRequestError,
    InvalidScopeError,
    InvalidTokenError,
    SlowDownError,
    UnauthorizedClientError,
    UnsupportedGrantTypeError,
    InvalidTargetError,
    ServerError,
} from './errors.js';
import crypto from 'node:crypto';
import debug from 'debug';
import { AccessToken, DeviceAuthorization, DeviceAuthorizationEndpointResponse, RefreshToken } from './types';
import { DEVICE_AUTHORIZATION_GRANT_TYPE, generateDeviceCode, generateDeviceUserCode, normalizeDeviceUserCode } from './deviceFlow';
import { OAuthServerModel } from './OAuthServerModel';
import { MemoryOAuthServerModel } from './MemoryOAuthServerModel';
import { validateChallenge } from './pkce';
import { ClientIdMetadataDocumentFetcher, ClientIdMetadataDocumentOptions, isClientIdMetadataDocumentUrl } from './cimd';

const log = debug('oauth:OAuthServer');
export const SUPPORTED_GRANT_TYPES = [
    'authorization_code',
    'refresh_token',
    'client_credentials',
    DEVICE_AUTHORIZATION_GRANT_TYPE,
] as const;
export type OAuthGrantType = (typeof SUPPORTED_GRANT_TYPES)[number];
export const DEFAULT_GRANT_TYPES: OAuthGrantType[] = ['authorization_code', 'refresh_token'];

type ErrorHandler = (
    step:
        | 'getClient'
        | 'registerClient'
        | 'authorize'
        | 'authenticate'
        | 'exchangeAuthorizationCode'
        | 'exchangeRefreshToken'
        | 'exchangeClientCredentials'
        | 'verifyAccessToken'
        | 'revokeToken'
        | 'requestDeviceAuthorization'
        | 'exchangeDeviceCode'
        | 'approveDeviceAuthorization'
        | 'denyDeviceAuthorization',
    error: Error,
    params?: any,
) => void;

const defaultErrorHandler: ErrorHandler = (step, error, params) => {
    log(`error: ${step}`, error, params);
};

export interface OAuthServerOptions {
    /**
     * The model to use for the OAuth server.
     * @default {@link MemoryOAuthServerModel}
     */
    model?: OAuthServerModel;

    /**
     * The URL to redirect the user to for authorization.
     *
     * This may be a consent screen hosted on the Authorization Server
     * or a custom consent screen hosted on another frontend,
     * like your web application.
     */
    authorizationUrl?: URL;

    /**
     * The scopes supported by this OAuth server.
     *
     * If the client does not include any scopes in the request, the server will default to all the supported scopes.
     *
     * Some MCP clients do not follow the spec and do not include any scopes in the request.
     */
    scopesSupported?: string[];

    /**
     * The lifetime of the access token in seconds.
     *
     * @default 1 hour
     */
    accessTokenLifetime?: number;

    /**
     * Whether to validate the resource indicator in the authorization request.
     *
     * @default true
     */
    strictResource?: boolean;

    /**
     * The number of seconds after which to expire issued client secrets, or 0 to prevent expiration of client secrets (not recommended).
     *
     * Public clients (clients registered with token_endpoint_auth_method = 'none') do not have a client secret and lives forever.
     *
     * @default 3 months
     */
    clientSecretLifetime?: number;

    /**
     * The lifetime of the refresh token in seconds.
     *
     * @default 2 weeks
     */
    refreshTokenLifetime?: number;

    /**
     * The lifetime of the authorization code in seconds.
     *
     * @default 5 minutes
     */
    authorizationCodeLifetime?: number;

    /**
     * The URL of the protected resource (RS) whose metadata we advertise.
     * If not provided, the resource param will not be validated.
     */
    resourceServerUrl?: URL;

    /**
     * The authorization server's issuer identifier, a URL using the "https" scheme
     * with no query or fragment components (localhost is allowed for development).
     *
     * Used as the `issuer` in the authorization server metadata (RFC 8414) served by
     * `mcpAuthRouter`, and appended as the `iss` query parameter (RFC 9207) to
     * authorization responses. Required when using `mcpAuthRouter`.
     */
    issuerUrl?: URL;

    /**
     * Modify the authorization redirect URL.
     * This can be used to add metadata to the authorization redirect URL, like the client name, client URI, or logo URI.
     * @param url The authorizationUrl with required oauth query string parameters set
     * @param client The client trying to authenticate
     * @param params The authorization parameters
     * @returns nothing, the url object is mutated
     */
    modifyAuthorizationRedirectUrl?: (url: URL, client: OAuthClientInformationFull, params: AuthorizationParams) => Promise<void> | void;

    /**
     * The auth router may swallow errors thrown in OAuthServer methods.
     */
    errorHandler?: ErrorHandler;

    /**
     * RFC 8628: URL where the user enters the `user_code` (device flow).
     * When set, device authorization endpoints are enabled and the model must implement device persistence methods.
     */
    deviceAuthorizationUrl?: URL;

    /**
     * Lifetime of the device code in seconds (RFC 8628 `expires_in`).
     * @default 900 (15 minutes)
     */
    deviceAuthorizationLifetime?: number;

    /**
     * Minimum interval in seconds between token polls while authorization is pending (RFC 8628 `interval`).
     * @default 5
     */
    devicePollIntervalSeconds?: number;
    /**
     * Enabled OAuth grant types.
     * @default ['authorization_code', 'refresh_token']
     */
    grantTypes?: OAuthGrantType[];
    /**
     * Enable RFC 7591 dynamic client registration (`/register`).
     * @default true
     */
    dynamicClientRegistration?: boolean;

    /**
     * Enable OAuth Client ID Metadata Documents (CIMD): clients use an HTTPS URL as their
     * `client_id` and this server fetches the client metadata from that URL.
     *
     * Enabling this makes the server issue outbound HTTPS requests to client-supplied URLs.
     * Loopback and IP-literal hosts are always rejected, but consider setting
     * {@link ClientIdMetadataDocumentOptions.validateClientIdUrl} (e.g. a domain allowlist)
     * if this server can reach internal services.
     *
     * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00
     * @default false
     */
    clientIdMetadataDocuments?: boolean | ClientIdMetadataDocumentOptions;
}

/**
 * The OAuth Server provider to be used with {@link mcpAuthRouter}.
 */
export class OAuthServer implements OAuthServerOptions, OAuthRegisteredClientsStore {
    model: OAuthServerModel;
    authorizationUrl?: URL;

    scopesSupported?: string[];

    accessTokenLifetime: number;
    refreshTokenLifetime: number;
    clientSecretLifetime: number;
    authorizationCodeLifetime: number;
    strictResource: boolean;
    resourceServerUrl?: URL;
    issuerUrl?: URL;
    modifyAuthorizationRedirectUrl?: OAuthServerOptions['modifyAuthorizationRedirectUrl'];
    errorHandler: ErrorHandler;
    grantTypes: OAuthGrantType[];
    dynamicClientRegistration: boolean;
    clientIdMetadataDocumentFetcher?: ClientIdMetadataDocumentFetcher;

    deviceAuthorizationUrl?: URL;
    deviceAuthorizationLifetime: number;
    devicePollIntervalSeconds: number;

    constructor(options: OAuthServerOptions) {
        this.model = options.model || new MemoryOAuthServerModel();
        this.authorizationUrl = options.authorizationUrl;
        this.scopesSupported = options.scopesSupported;
        this.accessTokenLifetime = options.accessTokenLifetime || 3600;
        this.refreshTokenLifetime = options.refreshTokenLifetime || 3600 * 24 * 14;
        this.clientSecretLifetime = options.clientSecretLifetime || 3 * 30 * 24 * 60 * 60;
        this.authorizationCodeLifetime = options.authorizationCodeLifetime || 5 * 60;
        this.strictResource = options.strictResource ?? true;
        this.resourceServerUrl = options.resourceServerUrl ? resourceUrlFromServerUrl(options.resourceServerUrl) : undefined;
        this.issuerUrl = options.issuerUrl;
        this.modifyAuthorizationRedirectUrl = options.modifyAuthorizationRedirectUrl;
        this.errorHandler = options.errorHandler || defaultErrorHandler;
        this.deviceAuthorizationUrl = options.deviceAuthorizationUrl;
        this.deviceAuthorizationLifetime = options.deviceAuthorizationLifetime ?? 900;
        this.devicePollIntervalSeconds = options.devicePollIntervalSeconds ?? 5;
        this.grantTypes = options.grantTypes ?? DEFAULT_GRANT_TYPES;
        this.dynamicClientRegistration = options.dynamicClientRegistration ?? true;
        if (options.clientIdMetadataDocuments) {
            this.clientIdMetadataDocumentFetcher = new ClientIdMetadataDocumentFetcher(
                typeof options.clientIdMetadataDocuments === 'object' ? options.clientIdMetadataDocuments : {},
            );
        }
        this.validateGrantTypesAndModelCapabilities();
    }

    private validateGrantTypesAndModelCapabilities(): void {
        const unsupportedGrant = this.grantTypes.find((grantType) => !SUPPORTED_GRANT_TYPES.includes(grantType));
        if (unsupportedGrant) {
            throw new Error(`Unsupported grant type in OAuthServer options: ${unsupportedGrant}`);
        }

        const m = this.model;
        if (this.grantTypes.includes('authorization_code')) {
            if (!this.authorizationUrl) {
                throw new Error('authorization_code grant requires authorizationUrl');
            }
            if (!m.saveAuthorizationCode || !m.consumeAuthorizationCode) {
                throw new Error(
                    'authorization_code grant requires OAuthServerModel methods: saveAuthorizationCode, consumeAuthorizationCode',
                );
            }
        }

        if (this.grantTypes.includes('refresh_token')) {
            if (!m.consumeRefreshToken) {
                throw new Error('refresh_token grant requires OAuthServerModel method: consumeRefreshToken');
            }
        }

        if (this.grantTypes.includes(DEVICE_AUTHORIZATION_GRANT_TYPE)) {
            if (!this.deviceAuthorizationUrl) {
                throw new Error('device_code grant requires deviceAuthorizationUrl');
            }
            if (
                !m.saveDeviceAuthorization ||
                !m.getDeviceAuthorizationByDeviceCode ||
                !m.getDeviceAuthorizationByUserCode ||
                !m.deleteDeviceAuthorization ||
                !m.consumeApprovedDeviceAuthorization ||
                !m.resolvePendingDeviceAuthorization
            ) {
                throw new Error(
                    'device_code grant requires OAuthServerModel device methods: saveDeviceAuthorization, getDeviceAuthorizationByDeviceCode, getDeviceAuthorizationByUserCode, deleteDeviceAuthorization, consumeApprovedDeviceAuthorization, resolvePendingDeviceAuthorization',
                );
            }
        }

        if (this.dynamicClientRegistration) {
            if (!this.model.registerClient) {
                throw new Error('dynamic client registration is not supported by this authorization server');
            }
        }

        if (this.clientIdMetadataDocumentFetcher) {
            if (!m.saveClientIdMetadataDocument || !m.getClientIdMetadataDocument) {
                throw new Error(
                    'clientIdMetadataDocuments requires OAuthServerModel methods: saveClientIdMetadataDocument, getClientIdMetadataDocument',
                );
            }
        }
    }

    async getClient(clientId: string) {
        try {
            if (this.clientIdMetadataDocumentFetcher && isClientIdMetadataDocumentUrl(clientId)) {
                const cached = await this.model.getClientIdMetadataDocument!(clientId);
                if (cached && cached.expiresAt > new Date()) {
                    this.validateClientIdMetadataDocument(cached.client);
                    return cached.client;
                }

                const document = await this.clientIdMetadataDocumentFetcher.fetchClient(clientId);
                this.validateClientIdMetadataDocument(document.client);

                // An expiresAt in the past means the response forbade caching (Cache-Control no-store/no-cache)
                if (document.expiresAt > new Date()) {
                    await this.model.saveClientIdMetadataDocument!(document);
                }

                return document.client;
            }

            return await this.model.getClient!(clientId);
        } catch (error) {
            this.errorHandler('getClient', error, { clientId });
            throw error;
        }
    }

    /**
     * Validates a client resolved from a Client ID Metadata Document against this server's
     * configuration. CIMD clients are public clients: they cannot hold a client_secret, and
     * private_key_jwt authentication is not supported by this server.
     */
    private validateClientIdMetadataDocument(client: OAuthClientInformationFull): void {
        if (client.token_endpoint_auth_method && client.token_endpoint_auth_method !== 'none') {
            throw new InvalidClientError(
                `Unsupported token_endpoint_auth_method for client_id metadata document client: ${client.token_endpoint_auth_method}`,
            );
        }

        // A metadata document is global and static - its grant_types describe the client's
        // capabilities across all authorization servers, not a demand on this one. Clients may
        // advertise grants only used with other servers (e.g. urn:ietf:params:oauth:grant-type:jwt-bearer),
        // so only reject when the client could not use any grant here at all; each flow
        // checks its specific grant at usage time.
        const grantTypes = client.grant_types?.length ? client.grant_types : ['authorization_code'];
        if (!grantTypes.some((grant) => this.grantTypes.includes(grant as OAuthGrantType))) {
            throw new InvalidClientError(`No supported grant_types in client_id metadata document: ${grantTypes.join(', ')}`);
        }
    }

    async registerClient(clientMetadata: OAuthClientMetadata) {
        try {
            if (!this.model.registerClient) {
                throw new UnsupportedGrantTypeError('dynamic client registration is not supported by this authorization server');
            }

            const isPublicClient = clientMetadata.token_endpoint_auth_method === 'none';

            // Generate client credentials
            const clientSecret = isPublicClient ? undefined : crypto.randomBytes(32).toString('hex');
            const clientIdIssuedAt = Math.floor(Date.now() / 1000);

            // Calculate client secret expiry time
            const clientsDoExpire = this.clientSecretLifetime > 0;
            const secretExpiryTime = clientsDoExpire ? clientIdIssuedAt + this.clientSecretLifetime : 0;
            const clientSecretExpiresAt = isPublicClient ? undefined : secretExpiryTime;

            // If omitted, the default behavior is that the client will use only the "authorization_code" Grant Type.
            clientMetadata.grant_types ||= ['authorization_code'];

            const client: OAuthClientInformationFull = {
                ...clientMetadata,
                client_id: crypto.randomUUID(),
                client_id_issued_at: Math.floor(Date.now() / 1000),
                client_secret: clientSecret,
                client_secret_expires_at: clientSecretExpiresAt,
            };

            const grantedGrants = client.grant_types?.filter((grant) => this.grantTypes.includes(grant as OAuthGrantType)) ?? [];
            if (!grantedGrants.length) {
                throw new UnsupportedGrantTypeError('Unsupported grant_type: ' + client.grant_types?.join(', '));
            }

            if (
                client.token_endpoint_auth_method &&
                client.token_endpoint_auth_method !== 'none' &&
                client.token_endpoint_auth_method !== 'client_secret_post'
            ) {
                throw new CustomOAuthError('unsupported_token_endpoint_auth_method', 'Unsupported token_endpoint_auth_method');
            }

            return await this.model.registerClient!(client);
        } catch (error) {
            this.errorHandler('registerClient', error, { clientMetadata });
            throw error;
        }
    }

    // Begins the authorization flow. Redirect to the consent screen.
    async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
        try {
            if (!this.grantTypes.includes('authorization_code')) {
                throw new UnsupportedGrantTypeError('authorization_code grant is not supported');
            }
            params.scopes = this.validateScope(params.scopes);

            this.validateResource(params.resource);

            // Start with required OAuth parameters
            const url = new URL(this.authorizationUrl!);

            url.searchParams.set('client_id', client.client_id);
            url.searchParams.set('response_type', 'code');
            url.searchParams.set('redirect_uri', params.redirectUri);
            url.searchParams.set('code_challenge', params.codeChallenge);
            url.searchParams.set('code_challenge_method', 'S256');

            // Add optional standard OAuth parameters
            if (params.state) url.searchParams.set('state', params.state);
            if (params.scopes?.length) url.searchParams.set('scope', params.scopes.join(' '));
            if (params.resource) url.searchParams.set('resource', params.resource.href);

            if (typeof this.modifyAuthorizationRedirectUrl === 'function') {
                await this.modifyAuthorizationRedirectUrl(url, client, params);
            }

            log('authorize', url.href);
            res.redirect(url.toString());
        } catch (error) {
            this.errorHandler('authorize', error, { client, params });
            throw error;
        }
    }

    // Finishes the authorization flow. Returns the authorization code to the client.
    async authenticate(client: OAuthClientInformationFull, params: AuthorizationParams, userId: string, res: Response) {
        try {
            if (!this.grantTypes.includes('authorization_code')) {
                throw new UnsupportedGrantTypeError('authorization_code grant is not supported');
            }
            params.scopes = this.validateScope(params.scopes);
            this.validateResource(params.resource);

            if (!client.redirect_uris.some((registered) => redirectUriMatches(params.redirectUri, registered))) {
                throw new InvalidRequestError('Unregistered redirect_uri');
            }

            const authorizationCode = this.generateToken();

            const searchParams = new URLSearchParams({
                code: authorizationCode,
            });
            if (params.state) {
                searchParams.set('state', params.state);
            }
            if (this.issuerUrl) {
                // RFC 9207: identify the authorization server in the authorization response
                searchParams.set('iss', this.issuerUrl.href);
            }

            await this.model.saveAuthorizationCode!(
                {
                    authorizationCode,
                    clientId: client.client_id,
                    userId,
                    expiresAt: new Date(Date.now() + this.authorizationCodeLifetime * 1000),
                    scopes: params.scopes || [],
                    resource: params.resource?.href,
                    codeChallenge: params.codeChallenge,
                    redirectUri: params.redirectUri,
                    state: params.state,
                },
                client,
            );

            const targetUrl = new URL(params.redirectUri);
            targetUrl.search = searchParams.toString();
            log('authenticate', { params, targetUrl });
            res.redirect(targetUrl.toString());
        } catch (error) {
            this.errorHandler('authenticate', error, { client, params, userId });
            throw error;
        }
    }

    async exchangeAuthorizationCode(
        client: OAuthClientInformationFull,
        authorizationCode: string,
        codeVerifier: string,
        redirectUri?: string, // the redirect URI used to obtain the authorization code, removed in OAuth 2.1
        resource?: URL,
    ): Promise<OAuthTokens> {
        try {
            if (!this.grantTypes.includes('authorization_code')) {
                throw new UnsupportedGrantTypeError('authorization_code grant is not supported');
            }
            if (!client.grant_types?.includes('authorization_code')) {
                throw new UnauthorizedClientError('Client is not authorized to use authorization_code grant');
            }

            // Fetching and invalidating the code in one atomic, client-scoped operation is
            // what makes it single-use (OAuth 2.1 section 4.1.3): of any number of requests
            // presenting this code concurrently, only one gets the record back and reaches
            // the token issuance below. Requests from any other client consume nothing.
            //
            // Every check from here on burns the code instead of allowing a retry. That is
            // deliberate - a failed code_verifier must not be retryable, or the challenge
            // could be brute-forced one request at a time.
            const codeData = await this.model.consumeAuthorizationCode!(authorizationCode, client.client_id);
            if (!codeData) {
                // Unknown, already used, or issued to a different client. RFC 6749 section
                // 5.2 maps all three to invalid_grant, and not saying which avoids
                // confirming another client's code to the caller.
                throw new InvalidGrantError('Invalid authorization code');
            }

            if (codeData.expiresAt < new Date()) {
                throw new InvalidGrantError('Authorization code has expired');
            }

            // OAuth 2.0 backwards compability
            if (redirectUri) {
                log('exchangeAuthorizationCode with redirect_uri', { redirectUri });
                if (codeData.redirectUri !== redirectUri) {
                    throw new InvalidGrantError(
                        `Authorization code was issued to a different redirect URI, ${codeData.redirectUri} != ${redirectUri}`,
                    );
                }
            }

            // The resource indicator in the token request must match the resource indicator in the authorization request.
            if (this.strictResource) {
                // ChatGPT doesn't send the resource indicator in authorization_code requests and thus breaks
                // https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#resource-parameter-implementation
                if (!resource) {
                    throw new InvalidTargetError('Resource indicator is required');
                }

                if (!codeData.resource) {
                    throw new ServerError('authorization code was issued without a resource indicator');
                }
            }

            // If a resource is provided, it must be valid
            if (
                codeData.resource &&
                resource &&
                !checkResourceAllowed({ requestedResource: resource, configuredResource: codeData.resource })
            ) {
                throw new InvalidTargetError(`Invalid resource: ${resource}, expected: ${codeData.resource}`);
            }

            validateChallenge(codeData.codeChallenge, codeVerifier);

            const token = this.generateToken();

            const tokenData: AccessToken = {
                token,
                clientId: client.client_id,
                userId: codeData.userId,
                scopes: codeData.scopes || [],
                expiresAt: new Date(Date.now() + this.accessTokenLifetime * 1000),
                resource: codeData.resource,
            };

            await this.model.saveAccessToken(tokenData, client);

            const newRefreshTokenData: RefreshToken = {
                token: this.generateToken(),
                clientId: client.client_id,
                userId: codeData.userId,
                scopes: codeData.scopes || [],
                expiresAt: new Date(Date.now() + this.refreshTokenLifetime * 1000),
                resource: codeData.resource,
            };
            await this.model.saveRefreshToken(newRefreshTokenData, client);

            log('exchangeAuthorizationCode', {
                clientId: client.client_id,
                userId: codeData.userId,
                authorizationCode,
                codeVerifier,
                redirectUri,
                resource,
            });

            return {
                access_token: token,
                refresh_token: newRefreshTokenData.token,
                token_type: 'bearer',
                expires_in: this.accessTokenLifetime,
                scope: (codeData.scopes || []).join(' '),
            };
        } catch (error) {
            this.errorHandler('exchangeAuthorizationCode', error, {
                client,
                authorizationCode,
                codeVerifier,
                redirectUri,
                resource,
            });

            throw error;
        }
    }

    async exchangeRefreshToken(
        client: OAuthClientInformationFull,
        refreshToken: string,
        scopes?: string[],
        resource?: URL,
    ): Promise<OAuthTokens> {
        try {
            if (!this.grantTypes.includes('refresh_token')) {
                throw new UnsupportedGrantTypeError('refresh_token grant is not supported');
            }
            // Rotated on every use, so the read must be atomic with the invalidation and
            // scoped to the client for the same reasons as exchangeAuthorizationCode.
            const refreshTokenData = await this.model.consumeRefreshToken!(refreshToken, client.client_id);
            if (!refreshTokenData) {
                // Unknown, already used, or issued to a different client.
                throw new InvalidGrantError('Invalid refresh token');
            }

            if (refreshTokenData.expiresAt < new Date()) {
                throw new InvalidGrantError('Refresh token has expired');
            }

            // The requested scope must not include additional scopes that were not issued in the original access token.
            // Typically this will not be included in the request, and if omitted,
            // the service should issue an access token with the same scope as was previously issued.
            if (scopes) {
                if (!scopes.every((scope) => refreshTokenData.scopes.includes(scope))) {
                    throw new InvalidScopeError('Invalid scope');
                }
            } else {
                scopes = refreshTokenData.scopes;
            }

            // If the refresh_token was issued with a resource indicator, the resource indicator in the token request must match the resource indicator in the refresh token.
            if (refreshTokenData.resource) {
                if (!resource) {
                    throw new InvalidTargetError('Resource indicator is required');
                }

                if (!checkResourceAllowed({ requestedResource: resource, configuredResource: refreshTokenData.resource })) {
                    throw new InvalidTargetError(`Invalid resource: ${resource}, expected: ${refreshTokenData.resource}`);
                }
            }

            const newAccessToken: AccessToken = {
                token: this.generateToken(),
                clientId: client.client_id,
                userId: refreshTokenData.userId,
                scopes: scopes || [],
                expiresAt: new Date(Date.now() + this.accessTokenLifetime * 1000),
                resource: refreshTokenData.resource,
            };
            await this.model.saveAccessToken(newAccessToken, client);

            const newRefreshTokenData: RefreshToken = {
                token: this.generateToken(),
                clientId: client.client_id,
                userId: refreshTokenData.userId,
                scopes: scopes || [],
                expiresAt: new Date(Date.now() + this.refreshTokenLifetime * 1000),
                resource: refreshTokenData.resource,
            };
            await this.model.saveRefreshToken(newRefreshTokenData, client);

            return {
                access_token: newAccessToken.token,
                refresh_token: newRefreshTokenData.token,
                token_type: 'bearer',
                expires_in: this.accessTokenLifetime,
                scope: (scopes || []).join(' '),
            };
        } catch (error) {
            this.errorHandler('exchangeRefreshToken', error, {
                client,
                refreshToken,
                scopes,
                resource,
            });
            throw error;
        }
    }

    async exchangeClientCredentials(client: OAuthClientInformationFull, scopes?: string[], resource?: URL): Promise<OAuthTokens> {
        try {
            if (!this.grantTypes.includes('client_credentials')) {
                throw new UnsupportedGrantTypeError('client_credentials grant is not supported');
            }
            if (!client.grant_types?.includes('client_credentials')) {
                throw new UnauthorizedClientError('Client is not authorized to use client_credentials grant');
            }

            const validatedScopes = this.validateScope(scopes);
            this.validateResource(resource);

            const accessToken: AccessToken = {
                token: this.generateToken(),
                clientId: client.client_id,
                scopes: validatedScopes || [],
                expiresAt: new Date(Date.now() + this.accessTokenLifetime * 1000),
                resource: resource?.href,
            };
            await this.model.saveAccessToken(accessToken, client);

            return {
                access_token: accessToken.token,
                token_type: 'bearer',
                expires_in: this.accessTokenLifetime,
                scope: (validatedScopes || []).join(' '),
            };
        } catch (error) {
            this.errorHandler('exchangeClientCredentials', error, {
                client,
                scopes,
                resource,
            });
            throw error;
        }
    }

    async verifyAccessToken(token: string): Promise<AuthInfo> {
        try {
            const tokenData = await this.model.getAccessToken(token);
            if (!tokenData) {
                throw new InvalidTokenError('Invalid token');
            }

            if (tokenData.expiresAt < new Date()) {
                throw new InvalidTokenError('Token has expired');
            }

            log('verifyAccessToken', { tokenData });

            this.validateScope(tokenData.scopes);
            this.validateResource(tokenData.resource);

            return {
                token,
                clientId: tokenData.clientId,
                scopes: tokenData.scopes,
                expiresAt: Math.floor(tokenData.expiresAt.getTime() / 1000),
                resource: tokenData.resource ? new URL(tokenData.resource) : undefined,
                userId: tokenData.userId,
            };
        } catch (error) {
            this.errorHandler('verifyAccessToken', error);
            throw error;
        }
    }

    async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
        try {
            const hint = request.token_type_hint;

            log('revokeToken', { client, request });

            switch (hint) {
                case 'access_token':
                    await this.model.revokeAccessToken(request.token);
                    break;
                case 'refresh_token':
                    await this.model.revokeRefreshToken(request.token);
                    break;
                case undefined:
                    await this.model.revokeAccessToken(request.token);
                    await this.model.revokeRefreshToken(request.token);
                    break;
                default:
                    throw new InvalidRequestError('Unsupported token_type_hint');
            }
        } catch (error) {
            this.errorHandler('revokeToken', error, { client, request });
            throw error;
        }
    }

    async requestDeviceAuthorization(
        client: OAuthClientInformationFull,
        params: { scopes?: string[]; resource?: URL },
    ): Promise<DeviceAuthorizationEndpointResponse> {
        try {
            if (!this.grantTypes.includes(DEVICE_AUTHORIZATION_GRANT_TYPE) || !this.deviceAuthorizationUrl) {
                throw new UnsupportedGrantTypeError('Device authorization is not supported');
            }

            const scopes = this.validateScope(params.scopes);
            this.validateResource(params.resource);

            if (!client.grant_types?.includes(DEVICE_AUTHORIZATION_GRANT_TYPE)) {
                throw new UnauthorizedClientError('Client is not authorized to use the device authorization grant');
            }

            let userCode: string | undefined;
            for (let attempt = 0; attempt < 32; attempt++) {
                const candidate = generateDeviceUserCode();
                const normalized = normalizeDeviceUserCode(candidate);
                const existing = await this.model.getDeviceAuthorizationByUserCode!(normalized);
                if (!existing) {
                    userCode = candidate;
                    break;
                }
            }
            if (!userCode) {
                throw new ServerError('Could not allocate user code');
            }

            const deviceCode = generateDeviceCode();
            const expiresAt = new Date(Date.now() + this.deviceAuthorizationLifetime * 1000);

            const device: DeviceAuthorization = {
                deviceCode,
                userCode,
                clientId: client.client_id,
                scopes: scopes || [],
                resource: params.resource?.href,
                expiresAt,
                pollIntervalSeconds: this.devicePollIntervalSeconds,
                status: 'pending',
            };

            await this.model.saveDeviceAuthorization!(device);

            const verificationUri = this.deviceAuthorizationUrl.href;
            const verificationUriComplete = new URL(this.deviceAuthorizationUrl.href);
            verificationUriComplete.searchParams.set('user_code', userCode);

            log('requestDeviceAuthorization', { clientId: client.client_id, userCode, expiresAt });

            return {
                device_code: deviceCode,
                user_code: userCode,
                verification_uri: verificationUri,
                verification_uri_complete: verificationUriComplete.href,
                expires_in: this.deviceAuthorizationLifetime,
                interval: this.devicePollIntervalSeconds,
            };
        } catch (error) {
            this.errorHandler('requestDeviceAuthorization', error, { client, params });
            throw error;
        }
    }

    async exchangeDeviceCode(client: OAuthClientInformationFull, deviceCode: string): Promise<OAuthTokens> {
        try {
            if (!this.grantTypes.includes(DEVICE_AUTHORIZATION_GRANT_TYPE) || !this.deviceAuthorizationUrl) {
                throw new UnsupportedGrantTypeError('Device authorization is not supported');
            }

            const device = await this.model.getDeviceAuthorizationByDeviceCode!(deviceCode);
            if (!device) {
                throw new InvalidGrantError('Invalid device code');
            }

            if (device.clientId !== client.client_id) {
                throw new InvalidGrantError('Device code was not issued to this client');
            }

            if (device.expiresAt < new Date()) {
                await this.model.deleteDeviceAuthorization!(deviceCode);
                throw new ExpiredTokenError('The device code has expired');
            }

            if (device.status === 'denied') {
                await this.model.deleteDeviceAuthorization!(deviceCode);
                throw new AccessDeniedError('The end-user denied the authorization request');
            }

            if (device.status === 'approved') {
                // Devices poll this endpoint on a timer, so two polls can arrive together the
                // moment the user approves. Claiming the authorization atomically is what
                // makes the device code single-use: the poll that loses gets undefined here
                // rather than a second set of tokens.
                const approved = await this.model.consumeApprovedDeviceAuthorization!(deviceCode, client.client_id);
                if (!approved) {
                    throw new InvalidGrantError('Invalid device code');
                }

                if (!approved.userId) {
                    throw new ServerError('Device authorization is missing user id');
                }

                const token = this.generateToken();
                const tokenData: AccessToken = {
                    token,
                    clientId: client.client_id,
                    userId: approved.userId,
                    scopes: approved.scopes || [],
                    expiresAt: new Date(Date.now() + this.accessTokenLifetime * 1000),
                    resource: approved.resource,
                };
                await this.model.saveAccessToken(tokenData, client);

                const newRefreshTokenData: RefreshToken = {
                    token: this.generateToken(),
                    clientId: client.client_id,
                    userId: approved.userId,
                    scopes: approved.scopes || [],
                    expiresAt: new Date(Date.now() + this.refreshTokenLifetime * 1000),
                    resource: approved.resource,
                };
                await this.model.saveRefreshToken(newRefreshTokenData, client);

                log('exchangeDeviceCode', { clientId: client.client_id, userId: approved.userId });

                return {
                    access_token: token,
                    refresh_token: newRefreshTokenData.token,
                    token_type: 'bearer',
                    expires_in: this.accessTokenLifetime,
                    scope: (approved.scopes || []).join(' '),
                };
            }

            const now = Date.now();
            if (device.lastPollResponseAtMs !== undefined && now - device.lastPollResponseAtMs < device.pollIntervalSeconds * 1000) {
                device.pollIntervalSeconds += 5;
                device.lastPollResponseAtMs = now;
                await this.model.saveDeviceAuthorization!(device);
                throw new SlowDownError('Polling too frequently');
            }

            device.lastPollResponseAtMs = now;
            await this.model.saveDeviceAuthorization!(device);
            throw new AuthorizationPendingError('The authorization request is still pending');
        } catch (error) {
            this.errorHandler('exchangeDeviceCode', error, { client, deviceCode });
            throw error;
        }
    }

    /**
     * Mark a pending device authorization as approved after the resource owner authenticated
     * (call from your verification UI when the user confirms).
     */
    async approveDeviceAuthorization(userCode: string, userId: string): Promise<void> {
        try {
            if (!this.grantTypes.includes(DEVICE_AUTHORIZATION_GRANT_TYPE) || !this.deviceAuthorizationUrl) {
                throw new UnsupportedGrantTypeError('Device authorization is not supported');
            }

            const normalized = normalizeDeviceUserCode(userCode);
            const device = await this.model.getDeviceAuthorizationByUserCode!(normalized);
            if (!device) {
                throw new InvalidGrantError('Unknown user code');
            }

            if (device.expiresAt < new Date()) {
                await this.model.deleteDeviceAuthorization!(device.deviceCode);
                throw new ExpiredTokenError('The device code has expired');
            }

            // Atomic pending -> approved, so a simultaneous approve and deny cannot both
            // believe they won and leave the outcome to whichever write landed last.
            const approved = await this.model.resolvePendingDeviceAuthorization!(normalized, 'approved', userId);
            if (!approved) {
                throw new InvalidRequestError('Device authorization is no longer pending');
            }

            log('approveDeviceAuthorization', { userId, clientId: approved.clientId });
        } catch (error) {
            this.errorHandler('approveDeviceAuthorization', error, { userCode, userId });
            throw error;
        }
    }

    /**
     * Mark a pending device authorization as denied (call from your verification UI when the user declines).
     */
    async denyDeviceAuthorization(userCode: string): Promise<void> {
        try {
            if (!this.grantTypes.includes(DEVICE_AUTHORIZATION_GRANT_TYPE) || !this.deviceAuthorizationUrl) {
                throw new UnsupportedGrantTypeError('Device authorization is not supported');
            }

            const normalized = normalizeDeviceUserCode(userCode);
            const device = await this.model.getDeviceAuthorizationByUserCode!(normalized);
            if (!device) {
                throw new InvalidGrantError('Unknown user code');
            }

            if (device.expiresAt < new Date()) {
                await this.model.deleteDeviceAuthorization!(device.deviceCode);
                throw new ExpiredTokenError('The device code has expired');
            }

            // Atomic pending -> denied. See approveDeviceAuthorization.
            const denied = await this.model.resolvePendingDeviceAuthorization!(normalized, 'denied');
            if (!denied) {
                throw new InvalidRequestError('Device authorization is no longer pending');
            }

            log('denyDeviceAuthorization', { clientId: denied.clientId });
        } catch (error) {
            this.errorHandler('denyDeviceAuthorization', error, { userCode });
            throw error;
        }
    }

    private generateToken(): string {
        return crypto.randomBytes(32).toString('base64');
    }

    /**
     * Validates requested scopes.
     *
     * Some MCP clients do not send scopes at all. If no scopes are requested,
     * we default to the scopes supported by the server.
     *
     * If a scope that is not supported by the server is requested, we throw an error.
     */
    private validateScope(scopes?: string[]): string[] | undefined {
        if (!scopes) {
            return this.scopesSupported;
        }

        if (this.scopesSupported && scopes && !scopes.every((scope) => this.scopesSupported!.includes(scope))) {
            throw new InvalidScopeError('Invalid scope: requested scope is not supported');
        }

        return scopes;
    }

    /**
     * Validates the resource indicator against the configured resourceServerUrl.
     *
     * If strictResource is not set, we do not validate the resource indicator and it's up to the user
     * to validate the resource indicator themselves, if desired.
     */
    private validateResource(resource?: string | URL): void {
        // Do not accept missing resource indicators if strictResource is set
        if (this.strictResource && !resource) {
            throw new InvalidTargetError('Invalid resource: resource is required');
        }

        // Validate the resource indicator if it is provided and the resourceServerUrl is configured
        if (
            resource &&
            this.resourceServerUrl &&
            !checkResourceAllowed({ requestedResource: resource, configuredResource: this.resourceServerUrl })
        ) {
            throw new InvalidTargetError(`Invalid resource: ${resource}, expected: ${this.resourceServerUrl}`);
        }
    }
}
