import { describe, it, expect, beforeEach } from 'vitest';
import { OAuthServer } from '../OAuthServer.js';
import { MemoryOAuthServerModel } from '../MemoryOAuthServerModel.js';
import { InvalidScopeError, InvalidTargetError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { RefreshToken } from '../types.js';
import { createTestClient } from './test-helpers.js';

describe('OAuthServer.exchangeRefreshToken', () => {
    let oauthServer: OAuthServer;
    let model: MemoryOAuthServerModel;
    let client: OAuthClientInformationFull;

    beforeEach(() => {
        model = new MemoryOAuthServerModel();
        oauthServer = new OAuthServer({
            model,
            authorizationUrl: new URL('http://localhost:3000/consent'),
            scopesSupported: ['mcp:tools', 'mcp:resources'],
            accessTokenLifetime: 3600,
            refreshTokenLifetime: 1209600,
        });

        client = createTestClient({
            redirect_uris: ['http://localhost:3000/callback'],
        });
    });

    it('should successfully exchange a valid refresh token for new tokens', async () => {
        // Create a refresh token
        const refreshToken: RefreshToken = {
            token: 'refresh-token-123',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 1000000), // Future date
        };

        await model.saveRefreshToken(refreshToken, client);

        const result = await oauthServer.exchangeRefreshToken(client, 'refresh-token-123');

        expect(result).toHaveProperty('access_token');
        expect(result).toHaveProperty('refresh_token');
        expect(result.token_type).toBe('bearer');
        expect(result.expires_in).toBe(3600);
        expect(result.scope).toBe('mcp:tools');

        // Verify old refresh token was revoked
        const oldToken = await model.getRefreshToken('refresh-token-123');
        expect(oldToken).toBeUndefined();

        // Verify new tokens were saved
        const newAccessToken = await model.getAccessToken(result.access_token!);
        expect(newAccessToken).toBeDefined();
        expect(newAccessToken?.userId).toBe('user-123');
        expect(newAccessToken?.clientId).toBe(client.client_id);
        expect(newAccessToken?.scopes).toEqual(['mcp:tools']);

        const newRefreshToken = await model.getRefreshToken(result.refresh_token!);
        expect(newRefreshToken).toBeDefined();
        expect(newRefreshToken?.userId).toBe('user-123');
        expect(newRefreshToken?.clientId).toBe(client.client_id);
    });

    it('should use original scopes when no scopes are requested', async () => {
        const refreshToken: RefreshToken = {
            token: 'refresh-token-456',
            clientId: client.client_id,
            userId: 'user-456',
            scopes: ['mcp:tools', 'mcp:resources'],
            expiresAt: new Date(Date.now() + 1000000),
        };

        await model.saveRefreshToken(refreshToken, client);

        const result = await oauthServer.exchangeRefreshToken(client, 'refresh-token-456');

        expect(result.scope).toBe('mcp:tools mcp:resources');

        const newAccessToken = await model.getAccessToken(result.access_token!);
        expect(newAccessToken?.scopes).toEqual(['mcp:tools', 'mcp:resources']);
    });

    it('should issue tokens with requested scopes when subset is provided', async () => {
        const refreshToken: RefreshToken = {
            token: 'refresh-token-789',
            clientId: client.client_id,
            userId: 'user-789',
            scopes: ['mcp:tools', 'mcp:resources'],
            expiresAt: new Date(Date.now() + 1000000),
        };

        await model.saveRefreshToken(refreshToken, client);

        // Request a subset of original scopes
        const result = await oauthServer.exchangeRefreshToken(client, 'refresh-token-789', ['mcp:tools']);

        expect(result.scope).toBe('mcp:tools');

        // New tokens should have the requested scopes
        const newAccessToken = await model.getAccessToken(result.access_token!);
        expect(newAccessToken?.scopes).toEqual(['mcp:tools']);

        const newRefreshToken = await model.getRefreshToken(result.refresh_token!);
        expect((newRefreshToken as any).scopes).toEqual(['mcp:tools']);
    });

    it('should throw error when refresh token is invalid', async () => {
        await expect(oauthServer.exchangeRefreshToken(client, 'non-existent-token')).rejects.toThrow('Invalid refresh token');
    });

    it('should throw error when refresh token is expired', async () => {
        const expiredToken: RefreshToken = {
            token: 'expired-refresh-token',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() - 1000), // Past date
        };

        await model.saveRefreshToken(expiredToken, client);

        await expect(oauthServer.exchangeRefreshToken(client, 'expired-refresh-token')).rejects.toThrow('Refresh token has expired');
    });

    it('should throw error when client ID does not match', async () => {
        const refreshToken: RefreshToken = {
            token: 'refresh-token-wrong-client',
            clientId: 'different-client-id',
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 1000000),
        };

        await model.saveRefreshToken(refreshToken, client);

        await expect(oauthServer.exchangeRefreshToken(client, 'refresh-token-wrong-client')).rejects.toThrow(
            'Refresh token was not issued to this client',
        );
    });

    it('should throw error when requesting invalid scopes', async () => {
        const refreshToken: RefreshToken = {
            token: 'refresh-token-invalid-scope',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 1000000),
        };

        await model.saveRefreshToken(refreshToken, client);

        await expect(
            oauthServer.exchangeRefreshToken(
                client,
                'refresh-token-invalid-scope',
                ['mcp:tools', 'invalid:scope'], // Requesting scope not in original
            ),
        ).rejects.toThrow(InvalidScopeError);
    });

    it('should validate resource indicator when both are provided', async () => {
        const resourceUrl = new URL('http://localhost:3000/mcp');
        const refreshToken1: RefreshToken = {
            token: 'refresh-token-with-resource-1',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 1000000),
            resource: resourceUrl.href,
        };

        await model.saveRefreshToken(refreshToken1, client);

        // Should succeed with matching resource
        const result = await oauthServer.exchangeRefreshToken(client, 'refresh-token-with-resource-1', undefined, resourceUrl);
        expect(result).toHaveProperty('access_token');

        // Create a new refresh token for the invalid resource test
        const refreshToken2: RefreshToken = {
            token: 'refresh-token-with-resource-2',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 1000000),
            resource: resourceUrl.href,
        };

        await model.saveRefreshToken(refreshToken2, client);

        // Should fail with different resource
        const differentResource = new URL('http://localhost:3000/different');
        await expect(
            oauthServer.exchangeRefreshToken(client, 'refresh-token-with-resource-2', undefined, differentResource),
        ).rejects.toThrow(InvalidTargetError);
    });

    it('should reject refresh token exchange when resource is not provided in request but was in original token', async () => {
        const resourceUrl = new URL('http://localhost:3000/mcp');
        const refreshToken: RefreshToken = {
            token: 'refresh-token-resource-optional',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 1000000),
            resource: resourceUrl.href,
        };

        await model.saveRefreshToken(refreshToken, client);

        await expect(oauthServer.exchangeRefreshToken(client, 'refresh-token-resource-optional')).rejects.toThrow(InvalidTargetError);
    });

    it('should preserve resource in new tokens', async () => {
        const resourceUrl = new URL('http://localhost:3000/mcp');
        const refreshToken: RefreshToken = {
            token: 'refresh-token-resource-preserve',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 1000000),
            resource: resourceUrl.href,
        };

        await model.saveRefreshToken(refreshToken, client);

        const result = await oauthServer.exchangeRefreshToken(client, 'refresh-token-resource-preserve', undefined, resourceUrl);

        const newAccessToken = await model.getAccessToken(result.access_token!);
        expect(newAccessToken?.resource).toBe(resourceUrl.href);

        const newRefreshTokenData = await model.getRefreshToken(result.refresh_token!);
        const newRefreshToken = newRefreshTokenData as any as RefreshToken;
        expect(newRefreshToken?.resource).toBe(resourceUrl.href);
    });

    it('should set correct expiration times for new tokens', async () => {
        const refreshToken: RefreshToken = {
            token: 'refresh-token-expiration',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 1000000),
        };

        await model.saveRefreshToken(refreshToken, client);

        const beforeExchange = Date.now();
        const result = await oauthServer.exchangeRefreshToken(client, 'refresh-token-expiration');
        const afterExchange = Date.now();

        const newAccessToken = await model.getAccessToken(result.access_token!);
        expect(newAccessToken?.expiresAt).toBeDefined();

        // Access token should expire in ~1 hour (3600 seconds)
        const accessTokenExpiry = newAccessToken!.expiresAt.getTime();
        const expectedAccessExpiry = beforeExchange + 3600 * 1000;
        expect(accessTokenExpiry).toBeGreaterThanOrEqual(expectedAccessExpiry - 1000);
        expect(accessTokenExpiry).toBeLessThanOrEqual(afterExchange + 3600 * 1000 + 1000);

        const newRefreshTokenData = await model.getRefreshToken(result.refresh_token!);
        const newRefreshToken = newRefreshTokenData as any as RefreshToken;
        expect(newRefreshToken?.expiresAt).toBeDefined();

        // Refresh token should expire in ~2 weeks (1209600 seconds)
        const refreshTokenExpiry = newRefreshToken!.expiresAt.getTime();
        const expectedRefreshExpiry = beforeExchange + 1209600 * 1000;
        expect(refreshTokenExpiry).toBeGreaterThanOrEqual(expectedRefreshExpiry - 1000);
        expect(refreshTokenExpiry).toBeLessThanOrEqual(afterExchange + 1209600 * 1000 + 1000);
    });

    it('should generate unique tokens for each exchange', async () => {
        const refreshToken: RefreshToken = {
            token: 'refresh-token-unique',
            clientId: client.client_id,
            userId: 'user-123',
            scopes: ['mcp:tools'],
            expiresAt: new Date(Date.now() + 1000000),
        };

        await model.saveRefreshToken(refreshToken, client);

        const result1 = await oauthServer.exchangeRefreshToken(client, 'refresh-token-unique');

        // The new refresh token is already saved by exchangeRefreshToken
        // Exchange it again using the new refresh token
        const result2 = await oauthServer.exchangeRefreshToken(client, result1.refresh_token!);

        // All tokens should be unique
        expect(result1.access_token).not.toBe(result2.access_token);
        expect(result1.refresh_token).not.toBe(result2.refresh_token);
        expect(result1.access_token).not.toBe(result1.refresh_token);
        expect(result2.access_token).not.toBe(result2.refresh_token);
    });
});
