import { describe, it, expect, beforeEach } from 'vitest';
import { OAuthServer } from '../OAuthServer.js';
import { MemoryOAuthServerModel } from '../MemoryOAuthServerModel.js';
import { InvalidGrantError, InvalidScopeError } from '../errors.js';
import type { OAuthServerModel } from '../OAuthServerModel.js';
import { createTestClient } from './test-helpers.js';

describe('refresh token reuse detection (revokeGrantOnRefreshTokenReuse)', () => {
    const client = createTestClient();
    const otherClient = createTestClient({ client_id: 'other-client' });
    let model: MemoryOAuthServerModel;

    const serverWith = (revokeGrantOnRefreshTokenReuse?: boolean) =>
        new OAuthServer({
            model,
            authorizationUrl: new URL('http://localhost:3000/consent'),
            scopesSupported: ['mcp:tools', 'mcp:resources'],
            strictResource: false,
            revokeGrantOnRefreshTokenReuse,
        });

    beforeEach(async () => {
        model = new MemoryOAuthServerModel();
        await model.saveRefreshToken(
            {
                token: 'first-refresh-token',
                clientId: client.client_id,
                userId: 'user-1',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                grantId: 'grant-1',
            },
            client,
        );
    });

    it('revokes the whole grant when a rotated refresh token is presented again', async () => {
        const oauthServer = serverWith(true);
        const rotated = await oauthServer.exchangeRefreshToken(client, 'first-refresh-token');

        await expect(oauthServer.exchangeRefreshToken(client, 'first-refresh-token')).rejects.toThrow(InvalidGrantError);

        expect(await model.getAccessToken(rotated.access_token)).toBeUndefined();
        await expect(oauthServer.exchangeRefreshToken(client, rotated.refresh_token!)).rejects.toThrow(InvalidGrantError);
    });

    it('leaves other grants of the same client alone', async () => {
        const oauthServer = serverWith(true);
        await model.saveRefreshToken(
            {
                token: 'second-grant-refresh-token',
                clientId: client.client_id,
                userId: 'user-1',
                scopes: ['mcp:tools'],
                expiresAt: new Date(Date.now() + 1000000),
                grantId: 'grant-2',
            },
            client,
        );

        await oauthServer.exchangeRefreshToken(client, 'first-refresh-token');
        await expect(oauthServer.exchangeRefreshToken(client, 'first-refresh-token')).rejects.toThrow(InvalidGrantError);

        await expect(oauthServer.exchangeRefreshToken(client, 'second-grant-refresh-token')).resolves.toHaveProperty('access_token');
    });

    it('does nothing for a token that was never issued', async () => {
        const oauthServer = serverWith(true);
        const rotated = await oauthServer.exchangeRefreshToken(client, 'first-refresh-token');

        await expect(oauthServer.exchangeRefreshToken(client, 'made-up-token')).rejects.toThrow(InvalidGrantError);

        expect(await model.getAccessToken(rotated.access_token)).toBeDefined();
    });

    it('does not let another client trigger the revocation', async () => {
        const oauthServer = serverWith(true);
        const rotated = await oauthServer.exchangeRefreshToken(client, 'first-refresh-token');

        await expect(oauthServer.exchangeRefreshToken(otherClient, 'first-refresh-token')).rejects.toThrow(InvalidGrantError);

        expect(await model.getAccessToken(rotated.access_token)).toBeDefined();
    });

    it('does not mistake a corrected retry for a replay', async () => {
        const oauthServer = serverWith(true);

        // Rejected for its scope: the token is consumed and then put back.
        await expect(oauthServer.exchangeRefreshToken(client, 'first-refresh-token', ['mcp:resources'])).rejects.toThrow(InvalidScopeError);

        const retried = await oauthServer.exchangeRefreshToken(client, 'first-refresh-token');
        expect(await model.getAccessToken(retried.access_token)).toBeDefined();
    });

    it('is off by default: a replay fails but the session survives', async () => {
        const oauthServer = serverWith();
        const rotated = await oauthServer.exchangeRefreshToken(client, 'first-refresh-token');

        await expect(oauthServer.exchangeRefreshToken(client, 'first-refresh-token')).rejects.toThrow(InvalidGrantError);

        expect(await model.getAccessToken(rotated.access_token)).toBeDefined();
        await expect(oauthServer.exchangeRefreshToken(client, rotated.refresh_token!)).resolves.toHaveProperty('access_token');
    });

    it('refuses to start without getConsumedRefreshToken on the model', () => {
        const incomplete: OAuthServerModel = Object.create(model, { getConsumedRefreshToken: { value: undefined } });

        expect(
            () =>
                new OAuthServer({
                    model: incomplete,
                    authorizationUrl: new URL('http://localhost:3000/consent'),
                    revokeGrantOnRefreshTokenReuse: true,
                }),
        ).toThrow('getConsumedRefreshToken');
    });
});

describe('MemoryOAuthServerModel consumed refresh tokens', () => {
    it('forgets a consumed token once it would have expired', async () => {
        const model = new MemoryOAuthServerModel();
        const client = createTestClient();
        await model.saveRefreshToken(
            { token: 'short-lived', clientId: client.client_id, scopes: [], expiresAt: new Date(Date.now() + 1000) },
            client,
        );
        await model.consumeRefreshToken('short-lived', client.client_id);
        expect(await model.getConsumedRefreshToken('short-lived', client.client_id)).toBeDefined();

        model.purgeExpired(new Date(Date.now() + 5000));

        expect(await model.getConsumedRefreshToken('short-lived', client.client_id)).toBeUndefined();
    });
});
