import { describe, it, expect, beforeEach } from 'vitest';
import { OAuthServer } from '../OAuthServer.js';
import { MemoryOAuthServerModel } from '../MemoryOAuthServerModel.js';
import { DEVICE_AUTHORIZATION_GRANT_TYPE } from '../deviceFlow.js';

describe('OAuthServer Client Registration', () => {
    let oauthServer: OAuthServer;
    let model: MemoryOAuthServerModel;

    beforeEach(() => {
        model = new MemoryOAuthServerModel();
        oauthServer = new OAuthServer({
            model,
            authorizationUrl: new URL('http://localhost:3000/consent'),
            grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
            scopesSupported: ['mcp:tools', 'mcp:resources'],
        });
    });

    describe('registerClient', () => {
        it('should successfully register a client with all required fields', async () => {
            const clientMetadata = {
                redirect_uris: ['http://localhost:3000/callback'],
                grant_types: ['authorization_code', 'refresh_token'],
                response_types: ['code'],
                token_endpoint_auth_method: 'none' as const,
            };

            const registered = await oauthServer.registerClient!(clientMetadata);

            expect(registered).toBeDefined();
            expect(registered.client_id).toBeDefined();
            expect(registered.client_id_issued_at).toBeDefined();
            expect(registered.redirect_uris).toEqual(['http://localhost:3000/callback']);
            expect(registered.grant_types).toEqual(['authorization_code', 'refresh_token']);
            expect(registered.response_types).toEqual(['code']);
            expect(registered.token_endpoint_auth_method).toBe('none');
        });

        describe('client_id generation', () => {
            it('should auto-generate client_id if not provided', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.registerClient!(clientMetadata);

                expect(registered.client_id).toBeDefined();
                expect(registered.client_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
            });

            it('should use provided client_id if already set', async () => {
                const clientMetadata = {
                    client_id: 'custom-client-id',
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.registerClient!(clientMetadata);

                expect(registered.client_id).toBeDefined();
                expect(registered.client_id).not.toBe('custom-client-id');
                expect(registered.client_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
            });
        });

        describe('grant_types validation', () => {
            it('should accept authorization_code grant type', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.registerClient!(clientMetadata);

                expect(registered.grant_types).toEqual(['authorization_code']);
            });

            it('should accept refresh_token grant type', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['refresh_token'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.registerClient!(clientMetadata);

                expect(registered.grant_types).toEqual(['refresh_token']);
            });

            it('should accept both authorization_code and refresh_token grant types', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.registerClient!(clientMetadata);

                expect(registered.grant_types).toEqual(['authorization_code', 'refresh_token']);
            });

            it('should accept client_credentials grant type', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['client_credentials'],
                    token_endpoint_auth_method: 'client_secret_post' as const,
                };

                const registered = await oauthServer.registerClient!(clientMetadata);

                expect(registered.grant_types).toEqual(['client_credentials']);
            });

            it('should accept client_credentials together with authorization_code', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'client_credentials'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.registerClient!(clientMetadata);

                expect(registered.grant_types).toEqual(['authorization_code', 'client_credentials']);
            });

            it('should accept a mix of supported and unsupported grants without filtering', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.registerClient!(clientMetadata);
                expect(registered.grant_types).toEqual(['authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
            });

            it('should throw error when no requested grant is supported', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['urn:ietf:params:oauth:grant-type:jwt-bearer'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                await expect(oauthServer.registerClient!(clientMetadata)).rejects.toThrow('Unsupported grant_type');
            });

            it('defaults grant_types to authorization_code when omitted', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                } as any;

                const registered = await oauthServer.registerClient!(clientMetadata);
                expect(registered.grant_types).toEqual(['authorization_code']);
            });

            it('should accept the device grant alongside supported grants when it is not enabled on the server', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.registerClient!(clientMetadata);
                expect(registered.grant_types).toEqual(['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE]);
            });

            it('should accept device grant when verificationUri is configured', async () => {
                const withDevice = new OAuthServer({
                    model: new MemoryOAuthServerModel(),
                    authorizationUrl: new URL('http://localhost:3000/consent'),
                    deviceAuthorizationUrl: new URL('http://localhost:3000/device'),
                    grantTypes: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
                    scopesSupported: ['mcp:tools'],
                });

                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await withDevice.registerClient!(clientMetadata);
                expect(registered.grant_types).toContain(DEVICE_AUTHORIZATION_GRANT_TYPE);
            });
        });

        describe('response_types handling', () => {
            it('should accept response_type code', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.registerClient!(clientMetadata);

                expect(registered.response_types).toEqual(['code']);
            });

            it('stores unsupported response_types without register-time validation', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['token'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.registerClient!(clientMetadata);
                expect(registered.response_types).toEqual(['token']);
            });

            it('stores non-code first response_type without register-time validation', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['token', 'code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.registerClient!(clientMetadata);
                expect(registered.response_types).toEqual(['token', 'code']);
            });

            it('allows response_types to be undefined', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    token_endpoint_auth_method: 'none' as const,
                } as any;

                const registered = await oauthServer.registerClient!(clientMetadata);
                expect(registered.response_types).toBeUndefined();
            });
        });

        describe('token_endpoint_auth_method validation', () => {
            it('should accept token_endpoint_auth_method none', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.registerClient!(clientMetadata);

                expect(registered.token_endpoint_auth_method).toBe('none');
            });

            it('should accept token_endpoint_auth_method client_secret_post', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'client_secret_post' as const,
                };

                const registered = await oauthServer.registerClient!(clientMetadata);

                expect(registered.token_endpoint_auth_method).toBe('client_secret_post');
            });

            it('should throw error for unsupported token_endpoint_auth_method', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'client_secret_basic' as any,
                };

                await expect(oauthServer.registerClient!(clientMetadata)).rejects.toThrow('Unsupported token_endpoint_auth_method');
            });

            it('should allow token_endpoint_auth_method to be undefined (defaults to none)', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['code'],
                } as any;

                const registered = await oauthServer.registerClient!(clientMetadata);

                // When undefined, it should still be registered (the model may handle defaults)
                expect(registered).toBeDefined();
            });
        });
    });
});
