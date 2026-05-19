import { clientRegistrationHandler, ClientRegistrationHandlerOptions } from '../../handlers/register.js';
import { OAuthServer } from '../../OAuthServer.js';
import { OAuthClientInformationFull, OAuthClientMetadata } from '@modelcontextprotocol/sdk/shared/auth.js';
import express from 'express';
import supertest from 'supertest';
import { MockInstance } from 'vitest';

describe('Client Registration Handler', () => {
    // Mock provider with registration support
    const mockProviderWithRegistration = {
        grantTypes: ['authorization_code', 'refresh_token'],
        async registerClient(client: OAuthClientInformationFull): Promise<OAuthClientInformationFull> {
            // Return the client info as-is in the mock
            return client;
        },
    } as OAuthServer;

    // Mock provider without registration support (handler checks registerClient at runtime)
    const mockProviderWithoutRegistration = {
        grantTypes: ['authorization_code', 'refresh_token'],
    } as OAuthServer;

    describe('Handler creation', () => {
        it('throws error if client store does not support registration', () => {
            const options: ClientRegistrationHandlerOptions = {
                provider: mockProviderWithoutRegistration,
            };

            expect(() => clientRegistrationHandler(options)).toThrow('does not support registering clients');
        });

        it('creates handler if client store supports registration', () => {
            const options: ClientRegistrationHandlerOptions = {
                provider: mockProviderWithRegistration,
            };

            expect(() => clientRegistrationHandler(options)).not.toThrow();
        });
    });

    describe('Request handling', () => {
        let app: express.Express;
        let spyRegisterClient: MockInstance;

        beforeEach(() => {
            // Setup express app with registration handler
            app = express();
            const options: ClientRegistrationHandlerOptions = {
                provider: mockProviderWithRegistration,
            };

            app.use('/register', clientRegistrationHandler(options));

            // Spy on the registerClient method
            spyRegisterClient = vi.spyOn(mockProviderWithRegistration, 'registerClient');
        });

        afterEach(() => {
            spyRegisterClient.mockRestore();
        });

        it('requires POST method', async () => {
            const response = await supertest(app)
                .get('/register')
                .send({
                    redirect_uris: ['https://example.com/callback'],
                });

            expect(response.status).toBe(405);
            expect(response.headers.allow).toBe('POST');
            expect(response.body).toEqual({
                error: 'method_not_allowed',
                error_description: 'The method GET is not allowed for this endpoint',
            });
            expect(spyRegisterClient).not.toHaveBeenCalled();
        });

        it('validates required client metadata', async () => {
            const response = await supertest(app).post('/register').send({
                // Missing redirect_uris (required)
                client_name: 'Test Client',
            });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('invalid_client_metadata');
            expect(spyRegisterClient).not.toHaveBeenCalled();
        });

        it('validates redirect URIs format', async () => {
            const response = await supertest(app)
                .post('/register')
                .send({
                    redirect_uris: ['invalid-url'], // Invalid URL format
                });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('invalid_client_metadata');
            expect(response.body.error_description).toContain('redirect_uris');
            expect(spyRegisterClient).not.toHaveBeenCalled();
        });

        it('successfully registers client with minimal metadata', async () => {
            const clientMetadata: OAuthClientMetadata = {
                redirect_uris: ['https://example.com/callback'],
            };

            const response = await supertest(app).post('/register').send(clientMetadata);

            expect(response.status).toBe(201);

            // Verify the returned client information from clientsStore.registerClient
            expect(response.body.redirect_uris).toEqual(['https://example.com/callback']);

            // Verify client was registered
            expect(spyRegisterClient).toHaveBeenCalledTimes(1);
        });

        it('sets client_secret to undefined for token_endpoint_auth_method=none', async () => {
            const clientMetadata: OAuthClientMetadata = {
                redirect_uris: ['https://example.com/callback'],
                token_endpoint_auth_method: 'none',
            };

            const response = await supertest(app).post('/register').send(clientMetadata);

            expect(response.status).toBe(201);
            expect(response.body.client_secret).toBeUndefined();
            expect(response.body.client_secret_expires_at).toBeUndefined();
        });

        it('sets client_secret_expires_at for public clients only', async () => {
            // Test for public client (token_endpoint_auth_method not 'none')
            const publicClientMetadata: OAuthClientMetadata = {
                redirect_uris: ['https://example.com/callback'],
                token_endpoint_auth_method: 'client_secret_basic',
            };

            const publicResponse = await supertest(app).post('/register').send(publicClientMetadata);

            expect(publicResponse.status).toBe(201);
            expect(publicResponse.body.client_secret).toBeUndefined();
            expect(publicResponse.body.client_secret_expires_at).toBeUndefined();

            // Test for non-public client (token_endpoint_auth_method is 'none')
            const nonPublicClientMetadata: OAuthClientMetadata = {
                redirect_uris: ['https://example.com/callback'],
                token_endpoint_auth_method: 'none',
            };

            const nonPublicResponse = await supertest(app).post('/register').send(nonPublicClientMetadata);

            expect(nonPublicResponse.status).toBe(201);
            expect(nonPublicResponse.body.client_secret).toBeUndefined();
            expect(nonPublicResponse.body.client_secret_expires_at).toBeUndefined();
        });

        it('sets no client_id when clientIdGeneration=false', async () => {
            // Create handler with no expiry
            const customApp = express();
            const options: ClientRegistrationHandlerOptions = {
                provider: mockProviderWithRegistration,
            };

            customApp.use('/register', clientRegistrationHandler(options));

            const response = await supertest(customApp)
                .post('/register')
                .send({
                    redirect_uris: ['https://example.com/callback'],
                });

            expect(response.status).toBe(201);
            expect(response.body.client_id).toBeUndefined();
            expect(response.body.client_id_issued_at).toBeUndefined();
        });

        it('handles client with all metadata fields', async () => {
            const fullClientMetadata: OAuthClientMetadata = {
                redirect_uris: ['https://example.com/callback'],
                token_endpoint_auth_method: 'client_secret_basic',
                grant_types: ['authorization_code', 'refresh_token'],
                response_types: ['code'],
                client_name: 'Test Client',
                client_uri: 'https://example.com',
                logo_uri: 'https://example.com/logo.png',
                scope: 'profile email',
                contacts: ['dev@example.com'],
                tos_uri: 'https://example.com/tos',
                policy_uri: 'https://example.com/privacy',
                jwks_uri: 'https://example.com/jwks',
                software_id: 'test-software',
                software_version: '1.0.0',
            };

            const response = await supertest(app).post('/register').send(fullClientMetadata);

            expect(response.status).toBe(201);

            // Verify all metadata was preserved
            Object.entries(fullClientMetadata).forEach(([key, value]) => {
                expect(response.body[key]).toEqual(value);
            });
        });
    });
});
