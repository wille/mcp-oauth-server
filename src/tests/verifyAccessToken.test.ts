import { describe, it, expect, beforeEach } from 'vitest';
import { OAuthServer } from '../OAuthServer.js';
import { MemoryOAuthServerModel } from '../MemoryOAuthServerModel.js';
import { InvalidScopeError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { InvalidTargetError } from '../InvalidTargetError.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { AccessToken } from '../types.js';
import { createTestClient } from './test-helpers.js';

describe('OAuthServer.verifyAccessToken', () => {
    let oauthServer: OAuthServer;
    let model: MemoryOAuthServerModel;
    let client: OAuthClientInformationFull;

    beforeEach(() => {
        model = new MemoryOAuthServerModel();
        oauthServer = new OAuthServer({
            model,
            authorizationUrl: new URL('http://localhost:3000/consent'),
            scopesSupported: ['mcp:tools', 'mcp:resources'],
        });

        client = createTestClient({
            redirect_uris: ['http://localhost:3000/callback'],
        });
    });

    it('should successfully verify a valid access token', async () => {
        const accessToken: AccessToken = {
            token: 'valid-access-token',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
        };

        await model.saveAccessToken(accessToken, client);

        const authInfo = await oauthServer.verifyAccessToken('valid-access-token');

        expect(authInfo.token).toBe('valid-access-token');
        expect(authInfo.clientId).toBe(client.client_id);
        expect(authInfo.userId).toBe('user-123');
        expect(authInfo.scopes).toEqual(['mcp:tools']);
        expect(authInfo.expiresAt).toBe(Math.floor(accessToken.expiresAt.getTime() / 1000));
    });

    it('should return undefined resource when token has no resource', async () => {
        const accessToken: AccessToken = {
            token: 'token-without-resource',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 3600000),
        };

        await model.saveAccessToken(accessToken, client);

        const authInfo = await oauthServer.verifyAccessToken('token-without-resource');

        expect(authInfo.resource).toBeUndefined();
    });

    it('should throw error for invalid/non-existent token', async () => {
        await expect(oauthServer.verifyAccessToken('non-existent-token')).rejects.toThrow('Invalid token');
    });

    it('should throw error for token with invalid scope', async () => {
        const accessToken: AccessToken = {
            token: 'token-invalid-scope',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['invalid:scope'],
            expiresAt: new Date(Date.now() + 3600000),
        };

        await model.saveAccessToken(accessToken, client);

        await expect(oauthServer.verifyAccessToken('token-invalid-scope')).rejects.toThrow(InvalidScopeError);
    });

    it('should throw error when resource does not match mcpServerUrl', async () => {
        const resourceServer = new OAuthServer({
            model,
            authorizationUrl: new URL('http://localhost:3000/consent'),
            scopesSupported: ['mcp:tools'],
            mcpServerUrl: new URL('http://localhost:3000/mcp'),
        });

        const accessToken: AccessToken = {
            token: 'token-wrong-resource',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 3600000),
            resource: 'http://localhost:3000/different',
        };

        await model.saveAccessToken(accessToken, client);

        await expect(resourceServer.verifyAccessToken('token-wrong-resource')).rejects.toThrow(InvalidTargetError);
    });

    it('should accept token with resource matching mcpServerUrl', async () => {
        const resourceServer = new OAuthServer({
            model,
            authorizationUrl: new URL('http://localhost:3000/consent'),
            scopesSupported: ['mcp:tools'],
            mcpServerUrl: new URL('http://localhost:3000/mcp'),
        });

        const accessToken: AccessToken = {
            token: 'token-correct-resource',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 3600000),
            resource: 'http://localhost:3000/mcp',
        };

        await model.saveAccessToken(accessToken, client);

        const authInfo = await resourceServer.verifyAccessToken('token-correct-resource');

        expect(authInfo).toBeDefined();
        expect(authInfo.resource?.href).toBe('http://localhost:3000/mcp');
    });

    it('should accept token without resource when mcpServerUrl is not configured', async () => {
        const accessToken: AccessToken = {
            token: 'token-no-resource-no-config',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 3600000),
        };

        await model.saveAccessToken(accessToken, client);

        const authInfo = await oauthServer.verifyAccessToken('token-no-resource-no-config');

        expect(authInfo).toBeDefined();
        expect(authInfo.resource).toBeUndefined();
    });

    it('should accept token with resource when mcpServerUrl is not configured', async () => {
        const accessToken: AccessToken = {
            token: 'token-with-resource-no-config',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 3600000),
            resource: 'http://localhost:3000/mcp',
        };

        await model.saveAccessToken(accessToken, client);

        const authInfo = await oauthServer.verifyAccessToken('token-with-resource-no-config');

        expect(authInfo).toBeDefined();
        expect(authInfo.resource?.href).toBe('http://localhost:3000/mcp');
    });

    it('should return correct expiresAt as seconds since epoch', async () => {
        const expiresAt = new Date();
        const accessToken: AccessToken = {
            token: 'token-expiration',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt,
        };

        await model.saveAccessToken(accessToken, client);

        const authInfo = await oauthServer.verifyAccessToken('token-expiration');

        expect(authInfo.expiresAt).toBe(Math.floor(expiresAt.getTime() / 1000));
    });

    it('should handle token with multiple scopes', async () => {
        const accessToken: AccessToken = {
            token: 'token-multiple-scopes',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools', 'mcp:resources'],
            expiresAt: new Date(Date.now() + 3600000),
        };

        await model.saveAccessToken(accessToken, client);

        const authInfo = await oauthServer.verifyAccessToken('token-multiple-scopes');

        expect(authInfo.scopes).toEqual(['mcp:tools', 'mcp:resources']);
    });

    it('should handle token with default scopes when none specified', async () => {
        const accessToken: AccessToken = {
            token: 'token-default-scopes',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools', 'mcp:resources'],
            expiresAt: new Date(Date.now() + 3600000),
        };

        await model.saveAccessToken(accessToken, client);

        const authInfo = await oauthServer.verifyAccessToken('token-default-scopes');

        expect(authInfo.scopes).toEqual(['mcp:tools', 'mcp:resources']);
    });

    it('should throw error for expired access token', async () => {
        const expiredToken: AccessToken = {
            token: 'expired-access-token',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() - 1000), // Past date
        };

        await model.saveAccessToken(expiredToken, client);

        await expect(oauthServer.verifyAccessToken('expired-access-token')).rejects.toThrow('Token has expired');
    });
});
