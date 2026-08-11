import { tokenHandler, TokenHandlerOptions } from '../../handlers/token.js';
import { OAuthServer } from '../../OAuthServer.js';
import { DEVICE_AUTHORIZATION_GRANT_TYPE } from '../../deviceFlow.js';
import { OAuthRegisteredClientsStore } from '../../clients.js';
import { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from '../../schemas.js';
import express, { Response } from 'express';
import supertest from 'supertest';
import { InvalidGrantError, InvalidTokenError } from '../../errors.js';
import { AuthInfo, AuthorizationParams } from '../../types.js';

const mockTokens = {
    access_token: 'mock_access_token',
    token_type: 'bearer',
    expires_in: 3600,
    refresh_token: 'mock_refresh_token',
};

const mockTokensWithIdToken = {
    ...mockTokens,
    id_token: 'mock_id_token',
};

describe('Token Handler', () => {
    // Mock client data
    const validClient: OAuthClientInformationFull = {
        client_id: 'valid-client',
        client_secret: 'valid-secret',
        redirect_uris: ['https://example.com/callback'],
        grant_types: ['authorization_code', 'refresh_token', 'client_credentials', DEVICE_AUTHORIZATION_GRANT_TYPE],
    };

    // Mock client store
    const mockClientStore: OAuthRegisteredClientsStore = {
        async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
            if (clientId === 'valid-client') {
                return validClient;
            }
            return undefined;
        },
    };

    // Mock provider (partial implementation — cast for handler options typing)
    let mockProvider: OAuthServer;
    let app: express.Express;

    beforeEach(() => {
        // Create fresh mocks for each test
        mockProvider = {
            getClient: async (clientId: string) => Promise.resolve(mockClientStore.getClient(clientId)),

            async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
                res.redirect('https://example.com/callback?code=mock_auth_code');
            },

            async exchangeAuthorizationCode(
                client: OAuthClientInformationFull,
                authorizationCode: string,
                codeVerifier?: string,
            ): Promise<OAuthTokens> {
                if (authorizationCode === 'valid_code') {
                    if (codeVerifier !== undefined && codeVerifier !== 'valid_verifier') {
                        throw new InvalidGrantError('code_verifier does not match the challenge');
                    }
                    return mockTokens;
                }
                throw new InvalidGrantError('The authorization code is invalid or has expired');
            },

            async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, scopes?: string[]): Promise<OAuthTokens> {
                if (refreshToken === 'valid_refresh_token') {
                    const response: OAuthTokens = {
                        access_token: 'new_mock_access_token',
                        token_type: 'bearer',
                        expires_in: 3600,
                        refresh_token: 'new_mock_refresh_token',
                    };

                    if (scopes) {
                        response.scope = scopes.join(' ');
                    }

                    return response;
                }
                throw new InvalidGrantError('The refresh token is invalid or has expired');
            },

            async exchangeClientCredentials(_client: OAuthClientInformationFull, scopes?: string[]): Promise<OAuthTokens> {
                const response: OAuthTokens = {
                    access_token: 'client_credentials_access_token',
                    token_type: 'bearer',
                    expires_in: 3600,
                };
                if (scopes) {
                    response.scope = scopes.join(' ');
                }
                return response;
            },

            async verifyAccessToken(token: string): Promise<AuthInfo> {
                if (token === 'valid_token') {
                    return {
                        token,
                        clientId: 'valid-client',
                        scopes: ['read', 'write'],
                        expiresAt: Date.now() / 1000 + 3600,
                    };
                }
                throw new InvalidTokenError('Token is invalid or expired');
            },

            async revokeToken(_client: OAuthClientInformationFull, _request: OAuthTokenRevocationRequest): Promise<void> {
                // Do nothing in mock
            },

            async exchangeDeviceCode(_client: OAuthClientInformationFull, deviceCode: string): Promise<OAuthTokens> {
                if (deviceCode === 'valid_device') {
                    return mockTokens;
                }
                throw new InvalidGrantError('Invalid device code');
            },

            grantTypes: ['authorization_code', 'refresh_token', 'client_credentials', DEVICE_AUTHORIZATION_GRANT_TYPE],
            deviceAuthorizationUrl: new URL('https://example.com/device'),
        } as OAuthServer;

        // Setup express app with token handler
        app = express();
        const options: TokenHandlerOptions = {
            provider: mockProvider,
        };
        app.use('/token', tokenHandler(options));
    });

    describe('Basic request validation', () => {
        it('requires POST method', async () => {
            const response = await supertest(app).get('/token').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'authorization_code',
            });

            expect(response.status).toBe(405);
            expect(response.headers.allow).toBe('POST');
            expect(response.body).toEqual({
                error: 'method_not_allowed',
                error_description: 'The method GET is not allowed for this endpoint',
            });
        });

        it('requires grant_type parameter', async () => {
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                // Missing grant_type
            });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('invalid_request');
        });

        it('rejects unsupported grant types', async () => {
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'password', // Unsupported grant type
            });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('unsupported_grant_type');
        });

        it('rejects grant types the client is not authorized for', async () => {
            const noRefreshClient: OAuthClientInformationFull = {
                ...validClient,
                client_id: 'no-refresh-client',
                grant_types: ['authorization_code'],
            };
            mockProvider.getClient = async (clientId: string) => {
                if (clientId === 'no-refresh-client') {
                    return noRefreshClient;
                }
                return undefined;
            };

            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'no-refresh-client',
                client_secret: 'valid-secret',
                grant_type: 'refresh_token',
                refresh_token: 'valid_refresh_token',
            });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('unauthorized_client');
        });
    });

    /**
     * RFC 6749 §5.2 separates the two reasons a grant can be refused: unsupported_grant_type is
     * the server not offering it, unauthorized_client is the client not being registered for it.
     * The server's own configuration decides first, so a grant this server does not offer gets
     * the same answer no matter what the client registered.
     */
    describe('Grant support precedence', () => {
        it.each([
            ['listed in the client’s grant_types', ['authorization_code', 'client_credentials']],
            ['absent from the client’s grant_types', ['authorization_code']],
        ])('reports unsupported_grant_type for a grant the server has disabled, %s', async (_label, clientGrants) => {
            mockProvider.grantTypes = ['authorization_code'];
            mockProvider.getClient = async () => ({ ...validClient, grant_types: clientGrants });

            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'client_credentials',
            });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('unsupported_grant_type');
        });

        it('still reports unauthorized_client when the server supports the grant', async () => {
            // The distinction is only useful if this case keeps its own error.
            mockProvider.grantTypes = ['authorization_code', 'client_credentials'];
            mockProvider.getClient = async () => ({ ...validClient, grant_types: ['authorization_code'] });

            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'client_credentials',
            });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('unauthorized_client');
        });
    });

    describe('Client authentication', () => {
        it('requires valid client credentials', async () => {
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'invalid-client',
                client_secret: 'wrong-secret',
                grant_type: 'authorization_code',
            });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('invalid_client');
        });

        it('accepts valid client credentials', async () => {
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'authorization_code',
                code: 'valid_code',
                code_verifier: 'valid_verifier',
            });

            expect(response.status).toBe(200);
        });
    });

    describe('Authorization code grant', () => {
        it('requires code parameter', async () => {
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'authorization_code',
                // Missing code
                code_verifier: 'valid_verifier',
            });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('invalid_request');
        });

        it('requires code_verifier parameter', async () => {
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'authorization_code',
                code: 'valid_code',
                // Missing code_verifier
            });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('invalid_request');
        });

        it('rejects authorization code exchange when code_verifier does not match', async () => {
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'authorization_code',
                code: 'valid_code',
                code_verifier: 'invalid_verifier',
            });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('invalid_grant');
            expect(response.body.error_description).toContain('code_verifier');
        });

        it('rejects expired or invalid authorization codes', async () => {
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'authorization_code',
                code: 'expired_code',
                code_verifier: 'valid_verifier',
            });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('invalid_grant');
        });

        it('returns tokens for valid code exchange', async () => {
            const mockExchangeCode = vi.spyOn(mockProvider, 'exchangeAuthorizationCode');
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                resource: 'https://api.example.com/resource',
                grant_type: 'authorization_code',
                code: 'valid_code',
                code_verifier: 'valid_verifier',
            });

            expect(response.status).toBe(200);
            expect(response.body.access_token).toBe('mock_access_token');
            expect(response.body.token_type).toBe('bearer');
            expect(response.body.expires_in).toBe(3600);
            expect(response.body.refresh_token).toBe('mock_refresh_token');
            expect(mockExchangeCode).toHaveBeenCalledWith(
                validClient,
                'valid_code',
                'valid_verifier',
                undefined, // redirect_uri
                new URL('https://api.example.com/resource'), // resource parameter
            );
        });

        it('returns id token in code exchange if provided', async () => {
            mockProvider.exchangeAuthorizationCode = async (
                client: OAuthClientInformationFull,
                authorizationCode: string,
                codeVerifier?: string,
            ): Promise<OAuthTokens> => {
                if (authorizationCode === 'valid_code') {
                    if (codeVerifier !== undefined && codeVerifier !== 'valid_verifier') {
                        throw new InvalidGrantError('code_verifier does not match the challenge');
                    }
                    return mockTokensWithIdToken;
                }
                throw new InvalidGrantError('The authorization code is invalid or has expired');
            };

            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'authorization_code',
                code: 'valid_code',
                code_verifier: 'valid_verifier',
            });

            expect(response.status).toBe(200);
            expect(response.body.id_token).toBe('mock_id_token');
        });
    });

    describe('Refresh token grant', () => {
        it('requires refresh_token parameter', async () => {
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'refresh_token',
                // Missing refresh_token
            });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('invalid_request');
        });

        it('rejects invalid refresh tokens', async () => {
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'refresh_token',
                refresh_token: 'invalid_refresh_token',
            });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('invalid_grant');
        });

        it('returns new tokens for valid refresh token', async () => {
            const mockExchangeRefresh = vi.spyOn(mockProvider, 'exchangeRefreshToken');
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                resource: 'https://api.example.com/resource',
                grant_type: 'refresh_token',
                refresh_token: 'valid_refresh_token',
            });

            expect(response.status).toBe(200);
            expect(response.body.access_token).toBe('new_mock_access_token');
            expect(response.body.token_type).toBe('bearer');
            expect(response.body.expires_in).toBe(3600);
            expect(response.body.refresh_token).toBe('new_mock_refresh_token');
            expect(mockExchangeRefresh).toHaveBeenCalledWith(
                validClient,
                'valid_refresh_token',
                undefined, // scopes
                new URL('https://api.example.com/resource'), // resource parameter
            );
        });

        it('respects requested scopes on refresh', async () => {
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'refresh_token',
                refresh_token: 'valid_refresh_token',
                scope: 'profile email',
            });

            expect(response.status).toBe(200);
            expect(response.body.scope).toBe('profile email');
        });
    });

    describe('Device code grant', () => {
        it('requires device_code', async () => {
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: DEVICE_AUTHORIZATION_GRANT_TYPE,
            });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('invalid_request');
        });

        it('returns tokens when exchangeDeviceCode succeeds', async () => {
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: DEVICE_AUTHORIZATION_GRANT_TYPE,
                device_code: 'valid_device',
            });

            expect(response.status).toBe(200);
            expect(response.body.access_token).toBe('mock_access_token');
        });
    });

    describe('Client credentials grant', () => {
        it('returns an access token for valid client credentials request', async () => {
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'client_credentials',
            });

            expect(response.status).toBe(200);
            expect(response.body.access_token).toBe('client_credentials_access_token');
            expect(response.body.token_type).toBe('bearer');
            expect(response.body.refresh_token).toBeUndefined();
        });

        it('passes requested scope and resource to provider', async () => {
            const mockExchangeClientCredentials = vi.spyOn(mockProvider, 'exchangeClientCredentials');
            const response = await supertest(app).post('/token').type('form').send({
                client_id: 'valid-client',
                client_secret: 'valid-secret',
                grant_type: 'client_credentials',
                scope: 'profile email',
                resource: 'https://api.example.com/resource',
            });

            expect(response.status).toBe(200);
            expect(mockExchangeClientCredentials).toHaveBeenCalledWith(
                validClient,
                ['profile', 'email'],
                new URL('https://api.example.com/resource'),
            );
        });
    });
});
