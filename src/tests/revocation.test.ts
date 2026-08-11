import { describe, it, expect, beforeEach } from 'vitest';
import express from 'express';
import supertest from 'supertest';
import { OAuthServer } from '../OAuthServer.js';
import { MemoryOAuthServerModel } from '../MemoryOAuthServerModel.js';
import { mcpAuthRouter } from '../router.js';
import { OAuthClientInformationFull, OAuthTokens } from '../schemas.js';
import { createExpressResponseMock, generatePKCEPair } from './test-helpers.js';

const ISSUER = new URL('https://auth.example.com');

/**
 * Token revocation, RFC 7009.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
 * @see https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
 */
describe('RFC 7009 token revocation', () => {
    let model: MemoryOAuthServerModel;
    let server: OAuthServer;
    let alice: OAuthClientInformationFull;
    let bob: OAuthClientInformationFull;
    let pkce: { codeVerifier: string; codeChallenge: string };

    beforeEach(async () => {
        model = new MemoryOAuthServerModel();
        server = new OAuthServer({
            model,
            issuerUrl: ISSUER,
            authorizationUrl: new URL('https://auth.example.com/consent'),
            scopesSupported: ['mcp:tools'],
            strictResource: false,
        });
        pkce = generatePKCEPair();

        alice = await server.registerClient({
            redirect_uris: ['https://alice.example.com/callback'],
            grant_types: ['authorization_code', 'refresh_token'],
            token_endpoint_auth_method: 'none',
        });
        bob = await server.registerClient({
            redirect_uris: ['https://bob.example.com/callback'],
            grant_types: ['authorization_code', 'refresh_token'],
            token_endpoint_auth_method: 'none',
        });
    });

    /** Complete an authorization code flow and return the issued tokens. */
    async function issueTokens(client: OAuthClientInformationFull): Promise<OAuthTokens> {
        const res = createExpressResponseMock({ trackRedirectUrl: true });
        await server.authenticate(
            client,
            { redirectUri: client.redirect_uris[0], codeChallenge: pkce.codeChallenge, scopes: ['mcp:tools'] },
            'user-1',
            res,
        );
        const code = new URL(res.getRedirectUrl!()).searchParams.get('code')!;
        return server.exchangeAuthorizationCode(client, code, pkce.codeVerifier);
    }

    describe('§2.1 the token must have been issued to the requesting client', () => {
        it('revokes the requesting client’s own access token', async () => {
            const tokens = await issueTokens(alice);

            await server.revokeToken(alice, { token: tokens.access_token });

            expect(await model.getAccessToken(tokens.access_token)).toBeUndefined();
        });

        it('leaves an access token issued to another client untouched', async () => {
            const tokens = await issueTokens(alice);

            await server.revokeToken(bob, { token: tokens.access_token });

            expect(await model.getAccessToken(tokens.access_token)).toBeDefined();
            // Still usable by the client it was issued to.
            await expect(server.verifyAccessToken(tokens.access_token)).resolves.toMatchObject({ clientId: alice.client_id });
        });

        it('revokes the requesting client’s own refresh token', async () => {
            const tokens = await issueTokens(alice);

            await server.revokeToken(alice, { token: tokens.refresh_token! });

            expect(await model.getRefreshToken(tokens.refresh_token!)).toBeUndefined();
        });

        it('leaves a refresh token issued to another client untouched', async () => {
            const tokens = await issueTokens(alice);

            await server.revokeToken(bob, { token: tokens.refresh_token! });

            expect(await model.getRefreshToken(tokens.refresh_token!)).toBeDefined();
            // Still redeemable by the client it was issued to.
            await expect(server.exchangeRefreshToken(alice, tokens.refresh_token!)).resolves.toHaveProperty('access_token');
        });
    });

    describe('§2.1 the search extends across all supported token types', () => {
        // "If the server is unable to locate the token using the given hint, it MUST extend
        // its search across all of its supported token types."
        it('revokes a refresh token submitted with token_type_hint=access_token', async () => {
            const tokens = await issueTokens(alice);

            await server.revokeToken(alice, { token: tokens.refresh_token!, token_type_hint: 'access_token' });

            expect(await model.getRefreshToken(tokens.refresh_token!)).toBeUndefined();
        });

        it('revokes an access token submitted with token_type_hint=refresh_token', async () => {
            const tokens = await issueTokens(alice);

            await server.revokeToken(alice, { token: tokens.access_token, token_type_hint: 'refresh_token' });

            expect(await model.getAccessToken(tokens.access_token)).toBeUndefined();
        });

        it('revokes when no hint is given', async () => {
            const tokens = await issueTokens(alice);

            await server.revokeToken(alice, { token: tokens.refresh_token! });

            expect(await model.getRefreshToken(tokens.refresh_token!)).toBeUndefined();
        });

        it('rejects an unrecognised token_type_hint', async () => {
            const tokens = await issueTokens(alice);

            await expect(server.revokeToken(alice, { token: tokens.access_token, token_type_hint: 'nonsense' })).rejects.toMatchObject({
                errorCode: 'invalid_request',
            });
        });
    });

    describe('§2.1 revoking a refresh token invalidates the grant', () => {
        // "If the particular token is a refresh token and the authorization server supports
        // the revocation of access tokens, then the authorization server SHOULD also
        // invalidate all access tokens based on the same authorization grant."
        it('revokes access tokens from the same grant, including ones issued before a rotation', async () => {
            const first = await issueTokens(alice);
            const rotated = await server.exchangeRefreshToken(alice, first.refresh_token!);

            // Both access tokens belong to one authorization; only the newest refresh token
            // is still live after rotation.
            expect(await model.getAccessToken(first.access_token)).toBeDefined();
            expect(await model.getAccessToken(rotated.access_token)).toBeDefined();

            await server.revokeToken(alice, { token: rotated.refresh_token! });

            expect(await model.getAccessToken(first.access_token)).toBeUndefined();
            expect(await model.getAccessToken(rotated.access_token)).toBeUndefined();
            expect(await model.getRefreshToken(rotated.refresh_token!)).toBeUndefined();
        });

        it('leaves a second, independent authorization by the same user and client alone', async () => {
            // The trap in cascading by clientId + userId: these two grants share both, but
            // disconnecting one session must not end the other.
            const sessionA = await issueTokens(alice);
            const sessionB = await issueTokens(alice);

            await server.revokeToken(alice, { token: sessionA.refresh_token! });

            expect(await model.getAccessToken(sessionA.access_token)).toBeUndefined();
            expect(await model.getAccessToken(sessionB.access_token)).toBeDefined();
            expect(await model.getRefreshToken(sessionB.refresh_token!)).toBeDefined();
        });

        it('keeps the grant when only an access token is revoked', async () => {
            // The reverse direction is a MAY in §2.1, and is declined: a client dropping one
            // access token has not asked to end its session.
            const tokens = await issueTokens(alice);

            await server.revokeToken(alice, { token: tokens.access_token });

            expect(await model.getAccessToken(tokens.access_token)).toBeUndefined();
            expect(await model.getRefreshToken(tokens.refresh_token!)).toBeDefined();
            await expect(server.exchangeRefreshToken(alice, tokens.refresh_token!)).resolves.toHaveProperty('access_token');
        });

        it('carries one grant id across rotations', async () => {
            const first = await issueTokens(alice);
            const rotated = await server.exchangeRefreshToken(alice, first.refresh_token!);

            const original = await model.getAccessToken(first.access_token);
            const afterRotation = await model.getAccessToken(rotated.access_token);

            expect(original!.grantId).toBeTruthy();
            expect(afterRotation!.grantId).toBe(original!.grantId);
        });

        it('does not cascade for a client that does not own the token', async () => {
            const tokens = await issueTokens(alice);

            await server.revokeToken(bob, { token: tokens.refresh_token! });

            expect(await model.getAccessToken(tokens.access_token)).toBeDefined();
            expect(await model.getRefreshToken(tokens.refresh_token!)).toBeDefined();
        });
    });

    describe('§2.2 the response never reveals whether the token existed', () => {
        // "The authorization server responds with HTTP status code 200 if the token has been
        // revoked successfully or if the client submitted an invalid token." Answering
        // differently for a token that exists but belongs to someone else would turn this
        // endpoint into an oracle for probing other clients' tokens.
        it('answers 200 with an identical body for its own, another client’s, and an unknown token', async () => {
            const aliceTokens = await issueTokens(alice);
            const bobTokens = await issueTokens(bob);

            const app = express();
            app.use(mcpAuthRouter({ provider: server }));

            const revoke = (clientId: string, token: string) =>
                supertest(app).post('/revoke').type('form').send({ client_id: clientId, token });

            const own = await revoke(alice.client_id, aliceTokens.access_token);
            const someoneElses = await revoke(alice.client_id, bobTokens.access_token);
            const unknown = await revoke(alice.client_id, 'no-such-token');

            for (const response of [own, someoneElses, unknown]) {
                expect(response.status).toBe(200);
                expect(response.body).toEqual({});
            }

            // Only Alice's token was actually revoked.
            expect(await model.getAccessToken(aliceTokens.access_token)).toBeUndefined();
            expect(await model.getAccessToken(bobTokens.access_token)).toBeDefined();
        });
    });
});
