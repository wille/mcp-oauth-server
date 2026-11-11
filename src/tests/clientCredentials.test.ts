import { beforeEach, describe, expect, it } from 'vitest';
import type { OAuthClientInformationFull } from '../schemas.js';
import { OAuthServer } from '../OAuthServer.js';
import { MemoryOAuthServerModel } from '../MemoryOAuthServerModel.js';
import { InvalidClientMetadataError, InvalidTargetError, UnauthorizedClientError } from '../errors.js';
import { createTestClient } from './test-helpers.js';

describe('OAuthServer.exchangeClientCredentials', () => {
    let oauthServer: OAuthServer;
    let model: MemoryOAuthServerModel;
    let client: OAuthClientInformationFull;

    beforeEach(() => {
        model = new MemoryOAuthServerModel();
        oauthServer = new OAuthServer({
            model,
            authorizationUrl: new URL('http://localhost:3000/consent'),
            grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
            scopesSupported: ['mcp:tools', 'mcp:resources'],
            accessTokenLifetime: 3600,
            strictResource: false,
        });

        client = createTestClient({
            grant_types: ['client_credentials'],
            token_endpoint_auth_method: 'client_secret_post',
            client_secret: 'test-secret',
        });
    });

    it('rejects a client without a secret (RFC 6749 §4.4: confidential clients only)', async () => {
        const publicClient = createTestClient({
            grant_types: ['client_credentials'],
            token_endpoint_auth_method: 'none',
        });

        await expect(oauthServer.exchangeClientCredentials(publicClient, ['mcp:tools'])).rejects.toThrow(UnauthorizedClientError);
    });

    it('refuses to register a public client for client_credentials', async () => {
        await expect(
            oauthServer.registerClient({
                redirect_uris: [],
                grant_types: ['client_credentials'],
                token_endpoint_auth_method: 'none',
            }),
        ).rejects.toThrow(InvalidClientMetadataError);
    });

    it('registers a confidential client for client_credentials', async () => {
        const registered = await oauthServer.registerClient({
            redirect_uris: [],
            grant_types: ['client_credentials'],
            token_endpoint_auth_method: 'client_secret_post',
        });

        expect(registered.client_secret).toBeDefined();
        await expect(oauthServer.exchangeClientCredentials(registered, ['mcp:tools'])).resolves.toMatchObject({ token_type: 'bearer' });
    });

    it('issues an access token without refresh token', async () => {
        const result = await oauthServer.exchangeClientCredentials(client, ['mcp:tools']);

        expect(result.access_token).toBeDefined();
        expect(result.token_type).toBe('bearer');
        expect(result.expires_in).toBe(3600);
        expect(result.scope).toBe('mcp:tools');
        expect(result.refresh_token).toBeUndefined();

        const stored = await model.getAccessToken(result.access_token);
        expect(stored).toBeDefined();
        expect(stored?.clientId).toBe(client.client_id);
        expect(stored?.userId).toBeUndefined();
        expect(stored?.scopes).toEqual(['mcp:tools']);
    });

    it('rejects clients that are not allowed to use client_credentials', async () => {
        const unauthorizedClient = createTestClient({
            grant_types: ['authorization_code', 'refresh_token'],
        });

        await expect(oauthServer.exchangeClientCredentials(unauthorizedClient)).rejects.toThrow(UnauthorizedClientError);
    });

    it('validates resource indicator in strict mode', async () => {
        const strictServer = new OAuthServer({
            model: new MemoryOAuthServerModel(),
            authorizationUrl: new URL('http://localhost:3000/consent'),
            grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
            strictResource: true,
            resourceServerUrl: new URL('http://localhost:3000/mcp'),
        });

        await expect(strictServer.exchangeClientCredentials(client)).rejects.toThrow(InvalidTargetError);
    });
});
