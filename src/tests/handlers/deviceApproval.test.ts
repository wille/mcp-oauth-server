import { describe, it, expect, beforeEach } from 'vitest';
import express from 'express';
import supertest from 'supertest';
import { approveDeviceAuthorizationHandler } from '../../handlers/approveDeviceAuthorization.js';
import { denyDeviceAuthorizationHandler } from '../../handlers/denyDeviceAuthorization.js';
import { OAuthServer } from '../../OAuthServer.js';
import { MemoryOAuthServerModel } from '../../MemoryOAuthServerModel.js';
import { DEVICE_AUTHORIZATION_GRANT_TYPE } from '../../deviceFlow.js';
import { OAuthClientInformationFull } from '../../schemas.js';

describe('device approval handlers', () => {
    let model: MemoryOAuthServerModel;
    let provider: OAuthServer;
    let client: OAuthClientInformationFull;
    let app: express.Express;

    beforeEach(async () => {
        model = new MemoryOAuthServerModel();
        provider = new OAuthServer({
            model,
            issuerUrl: new URL('https://auth.example.com'),
            authorizationUrl: new URL('https://auth.example.com/consent'),
            deviceAuthorizationUrl: new URL('https://auth.example.com/device'),
            grantTypes: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
            scopesSupported: ['mcp:tools'],
            strictResource: false,
        });
        client = await provider.registerClient({
            redirect_uris: ['http://localhost/cb'],
            grant_types: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
            token_endpoint_auth_method: 'none',
        });

        app = express();
        app.use('/approve', approveDeviceAuthorizationHandler({ provider, getUser: async () => 'user-1', rateLimit: false }));
        app.use('/deny', denyDeviceAuthorizationHandler({ provider, rateLimit: false }));
    });

    async function startDeviceFlow(): Promise<{ deviceCode: string; userCode: string }> {
        const res = await provider.requestDeviceAuthorization(client, { scopes: ['mcp:tools'] });
        return { deviceCode: res.device_code, userCode: res.user_code };
    }

    /**
     * A user_code decides which pending authorization gets bound to the caller's account, so it
     * must not be accepted from a URL: query strings reach access logs, Referer headers and
     * browser history, none of which see request bodies.
     */
    describe('user_code is only read from the request body', () => {
        it('approves when the code is in the body', async () => {
            const { deviceCode, userCode } = await startDeviceFlow();

            const response = await supertest(app).post('/approve').type('form').send({ user_code: userCode });

            expect(response.status).toBe(200);
            expect((await model.getDeviceAuthorizationByDeviceCode(deviceCode))!.status).toBe('approved');
        });

        it('ignores a user_code passed in the query string', async () => {
            const { deviceCode, userCode } = await startDeviceFlow();

            const response = await supertest(app)
                .post(`/approve?user_code=${encodeURIComponent(userCode)}`)
                .type('form')
                .send({});

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('invalid_request');
            expect((await model.getDeviceAuthorizationByDeviceCode(deviceCode))!.status).toBe('pending');
        });

        it('denies when the code is in the body', async () => {
            const { deviceCode, userCode } = await startDeviceFlow();

            const response = await supertest(app).post('/deny').type('form').send({ user_code: userCode });

            expect(response.status).toBe(200);
            expect((await model.getDeviceAuthorizationByDeviceCode(deviceCode))!.status).toBe('denied');
        });

        it('ignores a user_code passed in the query string when denying', async () => {
            const { deviceCode, userCode } = await startDeviceFlow();

            const response = await supertest(app)
                .post(`/deny?user_code=${encodeURIComponent(userCode)}`)
                .type('form')
                .send({});

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('invalid_request');
            expect((await model.getDeviceAuthorizationByDeviceCode(deviceCode))!.status).toBe('pending');
        });

        it('accepts a JSON body as well as a form body', async () => {
            const { deviceCode, userCode } = await startDeviceFlow();

            const response = await supertest(app).post('/approve').send({ user_code: userCode });

            expect(response.status).toBe(200);
            expect((await model.getDeviceAuthorizationByDeviceCode(deviceCode))!.status).toBe('approved');
        });
    });

    it('rejects methods other than POST', async () => {
        const { userCode } = await startDeviceFlow();

        const response = await supertest(app).get(`/approve?user_code=${encodeURIComponent(userCode)}`);

        expect(response.status).toBe(405);
    });
});
