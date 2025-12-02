import { AuthorizationParams, OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { Response } from 'express';
import { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { checkResourceAllowed, resourceUrlFromServerUrl } from '@modelcontextprotocol/sdk/shared/auth-utils.js';
import {
    CustomOAuthError,
    InvalidGrantError,
    InvalidRequestError,
    InvalidScopeError,
    InvalidTokenError,
    UnsupportedGrantTypeError,
    UnsupportedResponseTypeError,
    InvalidTargetError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import crypto from 'node:crypto';
import debug from 'debug';
import { AccessToken, RefreshToken } from './types';
import { OAuthServerModel } from './OAuthServerModel';
import { MemoryOAuthServerModel } from './MemoryOAuthServerModel';
import { validateChallenge } from './pkce';

const log = debug('oauth:OAuthServer');

type ErrorHandler = (
    step:
        | 'getClient'
        | 'registerClient'
        | 'authorize'
        | 'authenticate'
        | 'challengeForAuthorizationCode'
        | 'exchangeAuthorizationCode'
        | 'exchangeRefreshToken'
        | 'verifyAccessToken'
        | 'revokeToken',
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
    authorizationUrl: URL;

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
     * The MCP server URL
     *
     * If set, the RFC 8707 resource indicator will be validated against this URL.
     */
    mcpServerUrl?: URL;

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
     * The mcpAuthRouter will swallow errors thrown in a OAuthServerProvider methods.
     */
    errorHandler?: ErrorHandler;
}

/**
 * The OAuth Server provider to be used with {@link mcpAuthRouter} from [@modelcontextprotocol/typescript-sdk](https://github.com/modelcontextprotocol/typescript-sdk)
 * @implements OAuthServerProvider
 */
export class OAuthServer implements OAuthServerProvider, OAuthServerOptions {
    model: OAuthServerModel;
    authorizationUrl: URL;

    scopesSupported?: string[];

    accessTokenLifetime: number;
    refreshTokenLifetime: number;
    clientSecretLifetime: number;
    authorizationCodeLifetime: number;
    mcpServerUrl?: URL;
    modifyAuthorizationRedirectUrl?: OAuthServerOptions['modifyAuthorizationRedirectUrl'];
    errorHandler: ErrorHandler;

    constructor(options: OAuthServerOptions) {
        this.model = options.model || new MemoryOAuthServerModel();
        this.authorizationUrl = options.authorizationUrl;
        this.scopesSupported = options.scopesSupported;
        this.accessTokenLifetime = options.accessTokenLifetime || 3600;
        this.refreshTokenLifetime = options.refreshTokenLifetime || 3600 * 24 * 14;
        this.clientSecretLifetime = options.clientSecretLifetime || 3 * 30 * 24 * 60 * 60;
        this.authorizationCodeLifetime = options.authorizationCodeLifetime || 5 * 60;
        this.mcpServerUrl = options.mcpServerUrl ? resourceUrlFromServerUrl(options.mcpServerUrl) : undefined;
        this.modifyAuthorizationRedirectUrl = options.modifyAuthorizationRedirectUrl;
        this.errorHandler = options.errorHandler || defaultErrorHandler;
    }

    // Disable pkce validation in the mcp sdk as we do our validate challenges here
    readonly skipLocalPkceValidation = true;

    get clientsStore(): OAuthRegisteredClientsStore {
        return {
            // If model.registerClient is not implemented, dynamic client registration is unsupported.
            registerClient: this.model.registerClient ? this.registerClient.bind(this) : undefined,
            getClient: this.getClient.bind(this),
        };
    }

    private async getClient(clientId: string) {
        try {
            return await this.model.getClient!(clientId);
        } catch (error) {
            this.errorHandler('getClient', error, { clientId });
            throw error;
        }
    }

    private async registerClient(client: OAuthClientInformationFull) {
        try {
            // if AuthRouterOptions.clientRegistrationOptions.clientIdGeneration is explicitly set to false,
            // clientMetadata will not contain a client_id or client_secret
            client.client_id ||= crypto.randomUUID();
            client.client_id_issued_at ||= Math.floor(Date.now() / 1000);

            // Force the client to announce the grant types it supports
            if (
                !client.grant_types?.length ||
                !client.grant_types.every((grant) => grant === 'authorization_code' || grant === 'refresh_token')
            ) {
                throw new UnsupportedGrantTypeError('Unsupported grant_type');
            }

            if (!client.response_types?.length || client.response_types[0] !== 'code') {
                throw new UnsupportedResponseTypeError('Unsupported response_type');
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
            this.errorHandler('registerClient', error, { client });
            throw error;
        }
    }

    // Begins the authorization flow. Redirect to the consent screen.
    async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
        try {
            params.scopes = this.validateScope(params.scopes);

            this.validateResource(params.resource);

            // Start with required OAuth parameters
            const url = new URL(this.authorizationUrl);

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
            params.scopes = this.validateScope(params.scopes);
            this.validateResource(params.resource);

            if (!client.redirect_uris.includes(params.redirectUri)) {
                throw new InvalidRequestError('Unregistered redirect_uri');
            }

            const authorizationCode = this.generateToken();

            const searchParams = new URLSearchParams({
                code: authorizationCode,
            });
            if (params.state) {
                searchParams.set('state', params.state);
            }

            await this.model.saveAuthorizationCode(
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

    async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
        throw new Error('challengeForAuthorizationCode is not implemented');
    }

    async exchangeAuthorizationCode(
        client: OAuthClientInformationFull,
        authorizationCode: string,
        codeVerifier: string,
        redirectUri?: string, // the redirect URI used to obtain the authorization code, removed in OAuth 2.1
        resource?: URL,
    ): Promise<OAuthTokens> {
        try {
            const codeData = await this.model.getAuthorizationCode(authorizationCode);
            if (!codeData) {
                throw new InvalidGrantError('Invalid authorization code');
            }

            if (codeData.expiresAt < new Date()) {
                throw new InvalidGrantError('Authorization code has expired');
            }

            if (codeData.clientId !== client.client_id) {
                throw new InvalidGrantError(
                    `Authorization code was not issued to this client, ${codeData.clientId} != ${client.client_id}`,
                );
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
            if (codeData.resource) {
                if (!resource) {
                    throw new InvalidTargetError('Resource indicator is required');
                }

                if (!checkResourceAllowed({ requestedResource: resource, configuredResource: codeData.resource })) {
                    throw new InvalidTargetError(`Invalid resource: ${resource}, expected: ${codeData.resource}`);
                }
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

            await this.model.revokeAuthorizationCode(authorizationCode);

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
            const refreshTokenData = await this.model.getRefreshToken(refreshToken);
            if (!refreshTokenData) {
                throw new InvalidGrantError('Invalid refresh token');
            }

            if (refreshTokenData.expiresAt < new Date()) {
                throw new InvalidGrantError('Refresh token has expired');
            }

            if (refreshTokenData.clientId !== client.client_id) {
                throw new InvalidGrantError(
                    `Refresh token was not issued to this client, ${refreshTokenData.clientId} != ${client.client_id}`,
                );
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

            await this.model.revokeRefreshToken(refreshToken);

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
     * Validates the resource indicator against the configured mcpServerUrl.
     *
     * If strictResource is not set, we do not validate the resource indicator and it's up to the user
     * to validate the resource indicator themselves, if desired.
     */
    private validateResource(resource?: string | URL): void {
        if (!resource) {
            // throw new InvalidTargetError('Invalid resource: resource is required');
            return; // support clients not sending a resource indicator at all
        }
        if (!this.mcpServerUrl) {
            return;
        }
        if (!checkResourceAllowed({ requestedResource: resource, configuredResource: this.mcpServerUrl })) {
            throw new InvalidTargetError(`Invalid resource: ${resource}, expected: ${this.mcpServerUrl}`);
        }
    }
}
