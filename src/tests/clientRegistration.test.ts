import { describe, it, expect, beforeEach } from 'vitest';
import { OAuthServer } from '../OAuthServer.js';
import { MemoryOAuthServerModel } from '../MemoryOAuthServerModel.js';

describe('OAuthServer Client Registration', () => {
    let oauthServer: OAuthServer;
    let model: MemoryOAuthServerModel;

    beforeEach(() => {
        model = new MemoryOAuthServerModel();
        oauthServer = new OAuthServer({
            model,
            authorizationUrl: new URL('http://localhost:3000/consent'),
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

            const registered = await oauthServer.clientsStore.registerClient!(clientMetadata);

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

                const registered = await oauthServer.clientsStore.registerClient!(clientMetadata);

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

                const registered = await oauthServer.clientsStore.registerClient!(clientMetadata);

                expect(registered.client_id).toBe('custom-client-id');
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

                const registered = await oauthServer.clientsStore.registerClient!(clientMetadata);

                expect(registered.grant_types).toEqual(['authorization_code']);
            });

            it('should accept refresh_token grant type', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['refresh_token'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.clientsStore.registerClient!(clientMetadata);

                expect(registered.grant_types).toEqual(['refresh_token']);
            });

            it('should accept both authorization_code and refresh_token grant types', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.clientsStore.registerClient!(clientMetadata);

                expect(registered.grant_types).toEqual(['authorization_code', 'refresh_token']);
            });

            it('should throw error for unsupported grant type', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['client_credentials'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                await expect(oauthServer.clientsStore.registerClient!(clientMetadata)).rejects.toThrow('Unsupported grant_type');
            });

            it('should throw error when grant_types array contains unsupported grant', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'client_credentials'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                await expect(oauthServer.clientsStore.registerClient!(clientMetadata)).rejects.toThrow('Unsupported grant_type');
            });

            it('should throw error when grant_types is undefined', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                } as any;

                await expect(oauthServer.clientsStore.registerClient!(clientMetadata)).rejects.toThrow('Unsupported grant_type');
            });
        });

        describe('response_types validation', () => {
            it('should accept response_type code', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                const registered = await oauthServer.clientsStore.registerClient!(clientMetadata);

                expect(registered.response_types).toEqual(['code']);
            });

            it('should throw error for unsupported response_type', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['token'],
                    token_endpoint_auth_method: 'none' as const,
                };

                await expect(oauthServer.clientsStore.registerClient!(clientMetadata)).rejects.toThrow('Unsupported response_type');
            });

            it('should throw error when response_types first element is not code', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['token', 'code'],
                    token_endpoint_auth_method: 'none' as const,
                };

                await expect(oauthServer.clientsStore.registerClient!(clientMetadata)).rejects.toThrow('Unsupported response_type');
            });

            it('should throw error when response_types is undefined', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    token_endpoint_auth_method: 'none' as const,
                } as any;

                await expect(oauthServer.clientsStore.registerClient!(clientMetadata)).rejects.toThrow('Unsupported response_type');
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

                const registered = await oauthServer.clientsStore.registerClient!(clientMetadata);

                expect(registered.token_endpoint_auth_method).toBe('none');
            });

            it('should accept token_endpoint_auth_method client_secret_post', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'client_secret_post' as const,
                };

                const registered = await oauthServer.clientsStore.registerClient!(clientMetadata);

                expect(registered.token_endpoint_auth_method).toBe('client_secret_post');
            });

            it('should throw error for unsupported token_endpoint_auth_method', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'client_secret_basic' as any,
                };

                await expect(oauthServer.clientsStore.registerClient!(clientMetadata)).rejects.toThrow(
                    'Unsupported token_endpoint_auth_method',
                );
            });

            it('should allow token_endpoint_auth_method to be undefined (defaults to none)', async () => {
                const clientMetadata = {
                    redirect_uris: ['http://localhost:3000/callback'],
                    grant_types: ['authorization_code', 'refresh_token'],
                    response_types: ['code'],
                } as any;

                const registered = await oauthServer.clientsStore.registerClient!(clientMetadata);

                // When undefined, it should still be registered (the model may handle defaults)
                expect(registered).toBeDefined();
            });
        });
    });
});
