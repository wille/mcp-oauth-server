import { beforeEach, describe, expect, it } from 'vitest';
import type { OAuthClientInformationFull } from '../schemas.js';
import { OAuthServer } from '../OAuthServer.js';
import { MemoryOAuthServerModel } from '../MemoryOAuthServerModel.js';
import { InvalidTargetError, UnauthorizedClientError } from '../errors.js';
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
        });
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
