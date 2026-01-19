import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Response } from 'express';
import { OAuthServer } from '../OAuthServer.js';
import { MemoryOAuthServerModel } from '../MemoryOAuthServerModel.js';
import { InvalidRequestError, InvalidGrantError, InvalidScopeError, InvalidTargetError } from '../errors.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { AuthorizationCode } from '../types.js';
import { generatePKCEPair, createTestClient } from './test-helpers.js';

describe('OAuthServer Authorization Code Flow', () => {
    let oauthServer: OAuthServer;
    let model: MemoryOAuthServerModel;
    let client: OAuthClientInformationFull;
    let mockResponse: Response;
    let mockRedirect: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        model = new MemoryOAuthServerModel();
        oauthServer = new OAuthServer({
            model,
            authorizationUrl: new URL('http://localhost:3000/consent'),
            scopesSupported: ['mcp:tools', 'mcp:resources'],
            accessTokenLifetime: 3600,
            refreshTokenLifetime: 1209600,
            authorizationCodeLifetime: 300, // 5 minutes
            strictResource: false,
        });

        client = createTestClient();

        // Mock Express Response
        mockRedirect = vi.fn();
        mockResponse = {
            redirect: mockRedirect,
        } as unknown as Response;
    });

    describe('authorize', () => {
        it('should redirect to authorization URL with required parameters', async () => {
            const params = {
                redirectUri: 'http://localhost:3000/callback',
                codeChallenge: 'test-challenge',
            };

            await oauthServer.authorize(client, params, mockResponse);

            expect(mockRedirect).toHaveBeenCalledTimes(1);
            const redirectUrl = new URL(mockRedirect.mock.calls[0][0]);
            expect(redirectUrl.origin).toBe('http://localhost:3000');
            expect(redirectUrl.pathname).toBe('/consent');
            expect(redirectUrl.searchParams.get('client_id')).toBe(client.client_id);
            expect(redirectUrl.searchParams.get('response_type')).toBe('code');
            expect(redirectUrl.searchParams.get('redirect_uri')).toBe(params.redirectUri);
            expect(redirectUrl.searchParams.get('code_challenge')).toBe(params.codeChallenge);
            expect(redirectUrl.searchParams.get('code_challenge_method')).toBe('S256');
        });

        it('should include state parameter when provided', async () => {
            const params = {
                redirectUri: 'http://localhost:3000/callback',
                codeChallenge: 'test-challenge',
                state: 'test-state-123',
            };

            await oauthServer.authorize(client, params, mockResponse);

            const redirectUrl = new URL(mockRedirect.mock.calls[0][0]);
            expect(redirectUrl.searchParams.get('state')).toBe('test-state-123');
        });

        it('should include scope parameter when provided', async () => {
            const params = {
                redirectUri: 'http://localhost:3000/callback',
                codeChallenge: 'test-challenge',
                scopes: ['mcp:tools'],
            };

            await oauthServer.authorize(client, params, mockResponse);

            const redirectUrl = new URL(mockRedirect.mock.calls[0][0]);
            expect(redirectUrl.searchParams.get('scope')).toBe('mcp:tools');
        });

        it('should include resource parameter when provided', async () => {
            const resourceUrl = new URL('http://localhost:3000/mcp');
            const params = {
                redirectUri: 'http://localhost:3000/callback',
                codeChallenge: 'test-challenge',
                resource: resourceUrl,
            };

            await oauthServer.authorize(client, params, mockResponse);

            const redirectUrl = new URL(mockRedirect.mock.calls[0][0]);
            expect(redirectUrl.searchParams.get('resource')).toBe(resourceUrl.href);
        });

        it('should use default scopes when none provided', async () => {
            const params = {
                redirectUri: 'http://localhost:3000/callback',
                codeChallenge: 'test-challenge',
            };

            await oauthServer.authorize(client, params, mockResponse);

            const redirectUrl = new URL(mockRedirect.mock.calls[0][0]);
            expect(redirectUrl.searchParams.get('scope')).toBe('mcp:tools mcp:resources');
        });

        it('should throw error for invalid scope', async () => {
            const params = {
                redirectUri: 'http://localhost:3000/callback',
                codeChallenge: 'test-challenge',
                scopes: ['invalid:scope'],
            };

            await expect(oauthServer.authorize(client, params, mockResponse)).rejects.toThrow(InvalidScopeError);
        });

        it('should call modifyAuthorizationRedirectUrl when provided', async () => {
            const modifyUrl = vi.fn();
            const customServer = new OAuthServer({
                model,
                authorizationUrl: new URL('http://localhost:3000/consent'),
                scopesSupported: ['mcp:tools'],
                modifyAuthorizationRedirectUrl: modifyUrl,
                strictResource: false,
            });

            const params = {
                redirectUri: 'http://localhost:3000/callback',
                codeChallenge: 'test-challenge',
            };

            await customServer.authorize(client, params, mockResponse);

            expect(modifyUrl).toHaveBeenCalledTimes(1);
            expect(modifyUrl).toHaveBeenCalledWith(expect.any(URL), client, expect.objectContaining(params));
        });

        it('should validate resource when mcpServerUrl is configured', async () => {
            const resourceServer = new OAuthServer({
                model,
                authorizationUrl: new URL('http://localhost:3000/consent'),
                scopesSupported: ['mcp:tools'],
                resourceServerUrl: new URL('http://localhost:3000/mcp'),
            });

            const params = {
                redirectUri: 'http://localhost:3000/callback',
                codeChallenge: 'test-challenge',
                resource: new URL('http://localhost:3000/different'),
            };

            await expect(resourceServer.authorize(client, params, mockResponse)).rejects.toThrow(InvalidTargetError);
        });

        describe('resource indicator with strictResource', () => {
            it('should not throw when resource is missing and strictResource is false', async () => {
                const resourceServer = new OAuthServer({
                    model,
                    authorizationUrl: new URL('http://localhost:3000/consent'),
                    scopesSupported: ['mcp:tools'],
                    resourceServerUrl: new URL('http://localhost:3000/mcp'),
                    strictResource: false,
                });

                const params = {
                    redirectUri: 'http://localhost:3000/callback',
                    codeChallenge: 'test-challenge',
                };

                await resourceServer.authorize(client, params, mockResponse);

                expect(mockRedirect).toHaveBeenCalledTimes(1);
            });

            it('should throw when resource does not match and strictResource is false', async () => {
                const resourceServer = new OAuthServer({
                    model,
                    authorizationUrl: new URL('http://localhost:3000/consent'),
                    scopesSupported: ['mcp:tools'],
                    resourceServerUrl: new URL('http://localhost:3000/mcp'),
                    strictResource: false,
                });

                const params = {
                    redirectUri: 'http://localhost:3000/callback',
                    codeChallenge: 'test-challenge',
                    resource: new URL('http://localhost:3000/different'),
                };

                await expect(resourceServer.authorize(client, params, mockResponse)).rejects.toThrow(InvalidTargetError);
            });

            it('should throw when resource is missing and strictResource is true', async () => {
                const resourceServer = new OAuthServer({
                    model,
                    authorizationUrl: new URL('http://localhost:3000/consent'),
                    scopesSupported: ['mcp:tools'],
                    resourceServerUrl: new URL('http://localhost:3000/mcp'),
                    strictResource: true,
                });

                const params = {
                    redirectUri: 'http://localhost:3000/callback',
                    codeChallenge: 'test-challenge',
                };

                await expect(resourceServer.authorize(client, params, mockResponse)).rejects.toThrow(InvalidTargetError);
            });

            it('should throw when resource does not match and strictResource is true', async () => {
                const resourceServer = new OAuthServer({
                    model,
                    authorizationUrl: new URL('http://localhost:3000/consent'),
                    scopesSupported: ['mcp:tools'],
                    resourceServerUrl: new URL('http://localhost:3000/mcp'),
                    strictResource: true,
                });

                const params = {
                    redirectUri: 'http://localhost:3000/callback',
                    codeChallenge: 'test-challenge',
                    resource: new URL('http://localhost:3000/different'),
                };

                await expect(resourceServer.authorize(client, params, mockResponse)).rejects.toThrow(InvalidTargetError);
            });

            it('should succeed when resource matches and strictResource is true', async () => {
                const resourceServer = new OAuthServer({
                    model,
                    authorizationUrl: new URL('http://localhost:3000/consent'),
                    scopesSupported: ['mcp:tools'],
                    resourceServerUrl: new URL('http://localhost:3000/mcp'),
                    strictResource: true,
                });

                const params = {
                    redirectUri: 'http://localhost:3000/callback',
                    codeChallenge: 'test-challenge',
                    resource: new URL('http://localhost:3000/mcp'),
                };

                await resourceServer.authorize(client, params, mockResponse);

                expect(mockRedirect).toHaveBeenCalledTimes(1);
                const redirectUrl = new URL(mockRedirect.mock.calls[0][0]);
                expect(redirectUrl.searchParams.get('resource')).toBe('http://localhost:3000/mcp');
            });
        });
    });

    describe('authenticate', () => {
        it('should create authorization code and redirect to callback', async () => {
            const params = {
                redirectUri: 'http://localhost:3000/callback',
                codeChallenge: 'test-challenge',
                scopes: ['mcp:tools'],
            };
            const userId = 'user-123';

            await oauthServer.authenticate(client, params, userId, mockResponse);

            expect(mockRedirect).toHaveBeenCalledTimes(1);
            const redirectUrl = new URL(mockRedirect.mock.calls[0][0]);
            expect(redirectUrl.origin).toBe('http://localhost:3000');
            expect(redirectUrl.pathname).toBe('/callback');
            expect(redirectUrl.searchParams.has('code')).toBe(true);

            const code = redirectUrl.searchParams.get('code')!;
            const savedCode = await model.getAuthorizationCode(code);
            expect(savedCode).toBeDefined();
            expect(savedCode?.clientId).toBe(client.client_id);
            expect(savedCode?.userId).toBe(userId);
            expect(savedCode?.scopes).toEqual(['mcp:tools']);
            expect(savedCode?.codeChallenge).toBe('test-challenge');
            expect(savedCode?.redirectUri).toBe('http://localhost:3000/callback');
        });

        it('should include state in redirect when provided', async () => {
            const params = {
                redirectUri: 'http://localhost:3000/callback',
                codeChallenge: 'test-challenge',
                state: 'test-state-456',
            };
            const userId = 'user-123';

            await oauthServer.authenticate(client, params, userId, mockResponse);

            const redirectUrl = new URL(mockRedirect.mock.calls[0][0]);
            expect(redirectUrl.searchParams.get('state')).toBe('test-state-456');

            const code = redirectUrl.searchParams.get('code')!;
            const savedCode = await model.getAuthorizationCode(code);
            expect(savedCode?.state).toBe('test-state-456');
        });

        it('should set correct expiration time for authorization code', async () => {
            const params = {
                redirectUri: 'http://localhost:3000/callback',
                codeChallenge: 'test-challenge',
            };
            const userId = 'user-123';

            const beforeAuth = Date.now();
            await oauthServer.authenticate(client, params, userId, mockResponse);
            const afterAuth = Date.now();

            const redirectUrl = new URL(mockRedirect.mock.calls[0][0]);
            const code = redirectUrl.searchParams.get('code')!;
            const savedCode = await model.getAuthorizationCode(code);

            // Should expire in ~5 minutes (300 seconds)
            const expectedExpiry = beforeAuth + 300 * 1000;
            const actualExpiry = savedCode!.expiresAt.getTime();
            expect(actualExpiry).toBeGreaterThanOrEqual(expectedExpiry - 1000);
            expect(actualExpiry).toBeLessThanOrEqual(afterAuth + 300 * 1000 + 1000);
        });

        it('should throw error for unregistered redirect URI', async () => {
            const params = {
                redirectUri: 'http://localhost:3000/unregistered',
                codeChallenge: 'test-challenge',
            };
            const userId = 'user-123';

            await expect(oauthServer.authenticate(client, params, userId, mockResponse)).rejects.toThrow(InvalidRequestError);
        });

        it('should use default scopes when none provided', async () => {
            const params = {
                redirectUri: 'http://localhost:3000/callback',
                codeChallenge: 'test-challenge',
            };
            const userId = 'user-123';

            await oauthServer.authenticate(client, params, userId, mockResponse);

            const redirectUrl = new URL(mockRedirect.mock.calls[0][0]);
            const code = redirectUrl.searchParams.get('code')!;
            const savedCode = await model.getAuthorizationCode(code);
            expect(savedCode?.scopes).toEqual(['mcp:tools', 'mcp:resources']);
        });

        describe('resource indicator with strictResource', () => {
            it('should not throw when resource is missing and strictResource is false', async () => {
                const resourceServer = new OAuthServer({
                    model,
                    authorizationUrl: new URL('http://localhost:3000/consent'),
                    scopesSupported: ['mcp:tools'],
                    resourceServerUrl: new URL('http://localhost:3000/mcp'),
                    strictResource: false,
                });

                const params = {
                    redirectUri: 'http://localhost:3000/callback',
                    codeChallenge: 'test-challenge',
                };
                const userId = 'user-123';

                await resourceServer.authenticate(client, params, userId, mockResponse);

                expect(mockRedirect).toHaveBeenCalledTimes(1);
                const redirectUrl = new URL(mockRedirect.mock.calls[0][0]);
                expect(redirectUrl.searchParams.has('code')).toBe(true);
            });

            it('should throw when resource does not match and strictResource is false', async () => {
                const resourceServer = new OAuthServer({
                    model,
                    authorizationUrl: new URL('http://localhost:3000/consent'),
                    scopesSupported: ['mcp:tools'],
                    resourceServerUrl: new URL('http://localhost:3000/mcp'),
                    strictResource: false,
                });

                const params = {
                    redirectUri: 'http://localhost:3000/callback',
                    codeChallenge: 'test-challenge',
                    resource: new URL('http://localhost:3000/different'),
                };
                const userId = 'user-123';

                await expect(resourceServer.authenticate(client, params, userId, mockResponse)).rejects.toThrow(InvalidTargetError);
            });

            it('should throw when resource is missing and strictResource is true', async () => {
                const resourceServer = new OAuthServer({
                    model,
                    authorizationUrl: new URL('http://localhost:3000/consent'),
                    scopesSupported: ['mcp:tools'],
                    resourceServerUrl: new URL('http://localhost:3000/mcp'),
                    strictResource: true,
                });

                const params = {
                    redirectUri: 'http://localhost:3000/callback',
                    codeChallenge: 'test-challenge',
                };
                const userId = 'user-123';

                await expect(resourceServer.authenticate(client, params, userId, mockResponse)).rejects.toThrow(InvalidTargetError);
            });

            it('should throw when resource does not match and strictResource is true', async () => {
                const resourceServer = new OAuthServer({
                    model,
                    authorizationUrl: new URL('http://localhost:3000/consent'),
                    scopesSupported: ['mcp:tools'],
                    resourceServerUrl: new URL('http://localhost:3000/mcp'),
                    strictResource: true,
                });

                const params = {
                    redirectUri: 'http://localhost:3000/callback',
                    codeChallenge: 'test-challenge',
                    resource: new URL('http://localhost:3000/different'),
                };
                const userId = 'user-123';

                await expect(resourceServer.authenticate(client, params, userId, mockResponse)).rejects.toThrow(InvalidTargetError);
            });

            it('should succeed when resource matches and strictResource is true', async () => {
                const resourceServer = new OAuthServer({
                    model,
                    authorizationUrl: new URL('http://localhost:3000/consent'),
                    scopesSupported: ['mcp:tools'],
                    resourceServerUrl: new URL('http://localhost:3000/mcp'),
                    strictResource: true,
                });

                const params = {
                    redirectUri: 'http://localhost:3000/callback',
                    codeChallenge: 'test-challenge',
                    resource: new URL('http://localhost:3000/mcp'),
                };
                const userId = 'user-123';

                await resourceServer.authenticate(client, params, userId, mockResponse);

                expect(mockRedirect).toHaveBeenCalledTimes(1);
                const redirectUrl = new URL(mockRedirect.mock.calls[0][0]);
                const code = redirectUrl.searchParams.get('code')!;
                const savedCode = await model.getAuthorizationCode(code);
                expect(savedCode?.resource).toBe('http://localhost:3000/mcp');
            });

            it('should store resource in authorization code when provided', async () => {
                const resourceUrl = new URL('http://localhost:3000/mcp');
                const resourceServer = new OAuthServer({
                    model,
                    authorizationUrl: new URL('http://localhost:3000/consent'),
                    scopesSupported: ['mcp:tools'],
                    resourceServerUrl: resourceUrl,
                    strictResource: false,
                });

                const params = {
                    redirectUri: 'http://localhost:3000/callback',
                    codeChallenge: 'test-challenge',
                    resource: resourceUrl,
                };
                const userId = 'user-123';

                await resourceServer.authenticate(client, params, userId, mockResponse);

                const redirectUrl = new URL(mockRedirect.mock.calls[0][0]);
                const code = redirectUrl.searchParams.get('code')!;
                const savedCode = await model.getAuthorizationCode(code);
                expect(savedCode?.resource).toBe(resourceUrl.href);
            });
        });
    });

    describe('exchangeAuthorizationCode', () => {
        it('should successfully exchange valid authorization code for tokens', async () => {
            const { codeVerifier, codeChallenge } = generatePKCEPair();
            const authCode: AuthorizationCode = {
                authorizationCode: 'auth-code-valid',
                clientId: client.client_id,
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                codeChallenge,
                redirectUri: 'http://localhost:3000/callback',
            };

            await model.saveAuthorizationCode(authCode);

            const result = await oauthServer.exchangeAuthorizationCode(client, 'auth-code-valid', codeVerifier);

            expect(result).toHaveProperty('access_token');
            expect(result).toHaveProperty('refresh_token');
            expect(result.token_type).toBe('bearer');
            expect(result.expires_in).toBe(3600);
            expect(result.scope).toBe('mcp:tools');

            // Verify authorization code was revoked
            const revokedCode = await model.getAuthorizationCode('auth-code-valid');
            expect(revokedCode).toBeUndefined();

            // Verify tokens were saved
            const accessToken = await model.getAccessToken(result.access_token!);
            expect(accessToken).toBeDefined();
            expect(accessToken?.userId).toBe('user-123');
            expect(accessToken?.clientId).toBe(client.client_id);
            expect(accessToken?.scopes).toEqual(['mcp:tools']);

            const refreshToken = await model.getRefreshToken(result.refresh_token!);
            expect(refreshToken).toBeDefined();
        });

        it('should throw error for invalid authorization code', async () => {
            const { codeVerifier } = generatePKCEPair();
            await expect(oauthServer.exchangeAuthorizationCode(client, 'non-existent-code', codeVerifier)).rejects.toThrow(
                InvalidGrantError,
            );
        });

        it('should throw error for expired authorization code', async () => {
            const { codeVerifier, codeChallenge } = generatePKCEPair();
            const expiredCode: AuthorizationCode = {
                authorizationCode: 'auth-code-expired',
                clientId: client.client_id,
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() - 1000), // Past date
                codeChallenge,
                redirectUri: 'http://localhost:3000/callback',
            };

            await model.saveAuthorizationCode(expiredCode);

            await expect(oauthServer.exchangeAuthorizationCode(client, 'auth-code-expired', codeVerifier)).rejects.toThrow(
                InvalidGrantError,
            );
        });

        it('should throw error when client ID does not match', async () => {
            const { codeVerifier, codeChallenge } = generatePKCEPair();
            const authCode: AuthorizationCode = {
                authorizationCode: 'auth-code-wrong-client',
                clientId: 'different-client-id',
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                codeChallenge,
                redirectUri: 'http://localhost:3000/callback',
            };

            await model.saveAuthorizationCode(authCode);

            await expect(oauthServer.exchangeAuthorizationCode(client, 'auth-code-wrong-client', codeVerifier)).rejects.toThrow(
                InvalidGrantError,
            );
        });

        it('should throw error for invalid code_verifier', async () => {
            const { codeChallenge } = generatePKCEPair();
            const { codeVerifier: wrongCodeVerifier } = generatePKCEPair(); // Different verifier
            const authCode: AuthorizationCode = {
                authorizationCode: 'auth-code-invalid-verifier',
                clientId: client.client_id,
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                codeChallenge,
                redirectUri: 'http://localhost:3000/callback',
            };

            await model.saveAuthorizationCode(authCode);

            await expect(oauthServer.exchangeAuthorizationCode(client, 'auth-code-invalid-verifier', wrongCodeVerifier)).rejects.toThrow(
                InvalidGrantError,
            );
        });

        it('should validate redirect URI when provided (OAuth 2.0 compatibility)', async () => {
            const { codeVerifier, codeChallenge } = generatePKCEPair();
            const authCode: AuthorizationCode = {
                authorizationCode: 'auth-code-redirect',
                clientId: client.client_id,
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                codeChallenge,
                redirectUri: 'http://localhost:3000/callback',
            };

            await model.saveAuthorizationCode(authCode);

            // Should succeed with matching redirect URI
            const result = await oauthServer.exchangeAuthorizationCode(
                client,
                'auth-code-redirect',
                codeVerifier,
                'http://localhost:3000/callback',
            );
            expect(result).toHaveProperty('access_token');

            // Create new code for mismatch test
            const { codeVerifier: codeVerifier2, codeChallenge: codeChallenge2 } = generatePKCEPair();
            const authCode2: AuthorizationCode = {
                authorizationCode: 'auth-code-redirect-mismatch',
                clientId: client.client_id,
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                codeChallenge: codeChallenge2,
                redirectUri: 'http://localhost:3000/callback',
            };

            await model.saveAuthorizationCode(authCode2);

            // Should fail with different redirect URI
            await expect(
                oauthServer.exchangeAuthorizationCode(
                    client,
                    'auth-code-redirect-mismatch',
                    codeVerifier2,
                    'http://localhost:3000/different',
                ),
            ).rejects.toThrow(InvalidGrantError);
        });

        it('should validate resource indicator when both are provided', async () => {
            const resourceUrl = new URL('http://localhost:3000/mcp');
            const { codeVerifier, codeChallenge } = generatePKCEPair();
            const authCode: AuthorizationCode = {
                authorizationCode: 'auth-code-resource',
                clientId: client.client_id,
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                codeChallenge,
                redirectUri: 'http://localhost:3000/callback',
                resource: resourceUrl.href,
            };

            await model.saveAuthorizationCode(authCode);

            // Should succeed with matching resource
            const result = await oauthServer.exchangeAuthorizationCode(client, 'auth-code-resource', codeVerifier, undefined, resourceUrl);
            expect(result).toHaveProperty('access_token');

            // Create new code for mismatch test
            const { codeVerifier: codeVerifier2, codeChallenge: codeChallenge2 } = generatePKCEPair();
            const authCode2: AuthorizationCode = {
                authorizationCode: 'auth-code-resource-mismatch',
                clientId: client.client_id,
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                codeChallenge: codeChallenge2,
                redirectUri: 'http://localhost:3000/callback',
                resource: resourceUrl.href,
            };

            await model.saveAuthorizationCode(authCode2);

            // Should fail with different resource
            const differentResource = new URL('http://localhost:3000/different');
            await expect(
                oauthServer.exchangeAuthorizationCode(client, 'auth-code-resource-mismatch', codeVerifier2, undefined, differentResource),
            ).rejects.toThrow(InvalidTargetError);
        });

        it('should reject missing resource indicator when strictResource is true', async () => {
            const resourceServer = new OAuthServer({
                model,
                authorizationUrl: new URL('http://localhost:3000/consent'),
                scopesSupported: ['mcp:tools'],
                resourceServerUrl: new URL('http://localhost:3000/mcp'),
                strictResource: true,
            });

            const { codeVerifier, codeChallenge } = generatePKCEPair();
            const authCode: AuthorizationCode = {
                authorizationCode: 'auth-code-resource',
                clientId: client.client_id,
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                codeChallenge,
                redirectUri: 'http://localhost:3000/callback',
            };
            await model.saveAuthorizationCode(authCode);

            await expect(
                resourceServer.exchangeAuthorizationCode(client, 'auth-code-resource', codeVerifier, undefined, undefined),
            ).rejects.toThrow(InvalidTargetError);
        });

        it('should ignore missing resource indicator when strictResource is false', async () => {
            const resourceServer = new OAuthServer({
                model,
                authorizationUrl: new URL('http://localhost:3000/consent'),
                scopesSupported: ['mcp:tools'],
                resourceServerUrl: new URL('http://localhost:3000/mcp'),
                strictResource: false,
            });

            const { codeVerifier, codeChallenge } = generatePKCEPair();
            const authCode: AuthorizationCode = {
                authorizationCode: 'auth-code-resource',
                clientId: client.client_id,
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                codeChallenge,
                redirectUri: 'http://localhost:3000/callback',
            };
            await model.saveAuthorizationCode(authCode);

            const result = await resourceServer.exchangeAuthorizationCode(client, 'auth-code-resource', codeVerifier, undefined, undefined);
            expect(result).toBeTruthy();
        });

        it('should reject mismatching resource indicator when strictResource is false', async () => {
            const resourceServer = new OAuthServer({
                model,
                authorizationUrl: new URL('http://localhost:3000/consent'),
                scopesSupported: ['mcp:tools'],
                resourceServerUrl: new URL('http://localhost:3000/mcp'),
                strictResource: false,
            });

            const { codeVerifier, codeChallenge } = generatePKCEPair();
            const authCode: AuthorizationCode = {
                authorizationCode: 'auth-code-resource-mismatch',
                clientId: client.client_id,
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                codeChallenge,
                redirectUri: 'http://localhost:3000/callback',
                resource: 'http://localhost:3000/mcp',
            };
            await model.saveAuthorizationCode(authCode);

            await expect(
                resourceServer.exchangeAuthorizationCode(
                    client,
                    'auth-code-resource-mismatch',
                    codeVerifier,
                    undefined,
                    new URL('http://localhost:3000/different'),
                ),
            ).rejects.toThrow(InvalidTargetError);
        });

        it('should preserve resource in new tokens', async () => {
            const resourceUrl = new URL('http://localhost:3000/mcp');
            const { codeVerifier, codeChallenge } = generatePKCEPair();
            const authCode: AuthorizationCode = {
                authorizationCode: 'auth-code-resource-preserve',
                clientId: client.client_id,
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                codeChallenge,
                redirectUri: 'http://localhost:3000/callback',
                resource: resourceUrl.href,
            };

            await model.saveAuthorizationCode(authCode);

            const result = await oauthServer.exchangeAuthorizationCode(
                client,
                'auth-code-resource-preserve',
                codeVerifier,
                undefined,
                resourceUrl,
            );

            const accessToken = await model.getAccessToken(result.access_token!);
            expect(accessToken?.resource).toBe(resourceUrl.href);

            const refreshToken = await model.getRefreshToken(result.refresh_token!);
            expect((refreshToken as any).resource).toBe(resourceUrl.href);
        });

        it('should set correct expiration times for tokens', async () => {
            const { codeVerifier, codeChallenge } = generatePKCEPair();
            const authCode: AuthorizationCode = {
                authorizationCode: 'auth-code-expiration',
                clientId: client.client_id,
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                codeChallenge,
                redirectUri: 'http://localhost:3000/callback',
            };

            await model.saveAuthorizationCode(authCode);

            const beforeExchange = Date.now();
            const result = await oauthServer.exchangeAuthorizationCode(client, 'auth-code-expiration', codeVerifier);
            const afterExchange = Date.now();

            const accessToken = await model.getAccessToken(result.access_token!);
            expect(accessToken?.expiresAt).toBeDefined();

            // Access token should expire in ~1 hour (3600 seconds)
            const accessTokenExpiry = accessToken!.expiresAt.getTime();
            const expectedAccessExpiry = beforeExchange + 3600 * 1000;
            expect(accessTokenExpiry).toBeGreaterThanOrEqual(expectedAccessExpiry - 1000);
            expect(accessTokenExpiry).toBeLessThanOrEqual(afterExchange + 3600 * 1000 + 1000);

            const refreshTokenData = await model.getRefreshToken(result.refresh_token!);
            const refreshToken = refreshTokenData as any;
            expect(refreshToken?.expiresAt).toBeDefined();

            // Refresh token should expire in ~2 weeks (1209600 seconds)
            const refreshTokenExpiry = refreshToken!.expiresAt.getTime();
            const expectedRefreshExpiry = beforeExchange + 1209600 * 1000; // Uses refreshTokenLifetime
            expect(refreshTokenExpiry).toBeGreaterThanOrEqual(expectedRefreshExpiry - 1000);
            expect(refreshTokenExpiry).toBeLessThanOrEqual(afterExchange + 1209600 * 1000 + 1000);
        });

        it('should generate unique tokens for each exchange', async () => {
            const { codeVerifier: codeVerifier1, codeChallenge: codeChallenge1 } = generatePKCEPair();
            const { codeVerifier: codeVerifier2, codeChallenge: codeChallenge2 } = generatePKCEPair();
            const authCode1: AuthorizationCode = {
                authorizationCode: 'auth-code-unique-1',
                clientId: client.client_id,
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                codeChallenge: codeChallenge1,
                redirectUri: 'http://localhost:3000/callback',
            };

            const authCode2: AuthorizationCode = {
                authorizationCode: 'auth-code-unique-2',
                clientId: client.client_id,
                userId: 'user-123',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                codeChallenge: codeChallenge2,
                redirectUri: 'http://localhost:3000/callback',
            };

            await model.saveAuthorizationCode(authCode1);
            await model.saveAuthorizationCode(authCode2);

            const result1 = await oauthServer.exchangeAuthorizationCode(client, 'auth-code-unique-1', codeVerifier1);
            const result2 = await oauthServer.exchangeAuthorizationCode(client, 'auth-code-unique-2', codeVerifier2);

            // All tokens should be unique
            expect(result1.access_token).not.toBe(result2.access_token);
            expect(result1.refresh_token).not.toBe(result2.refresh_token);
            expect(result1.access_token).not.toBe(result1.refresh_token);
            expect(result2.access_token).not.toBe(result2.refresh_token);
        });
    });
});
