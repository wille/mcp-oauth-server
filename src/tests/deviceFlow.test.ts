import { describe, it, expect, vi, afterEach } from 'vitest';
import crypto from 'node:crypto';
import express from 'express';
import supertest from 'supertest';
import { mcpAuthRouter } from '../router.js';
import { OAuthServer } from '../OAuthServer.js';
import { MemoryOAuthServerModel } from '../MemoryOAuthServerModel.js';
import { DEVICE_AUTHORIZATION_GRANT_TYPE, generateDeviceUserCode, normalizeDeviceUserCode } from '../deviceFlow.js';

function createDeviceFlowApp() {
    const model = new MemoryOAuthServerModel();
    const provider = new OAuthServer({
        model,
        issuerUrl: new URL('http://127.0.0.1/'),
        authorizationUrl: new URL('http://127.0.0.1/consent'),
        deviceAuthorizationUrl: new URL('http://127.0.0.1/device'),
        grantTypes: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
        scopesSupported: ['mcp:tools'],
        strictResource: false,
    });
    const app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use(
        mcpAuthRouter({
            provider,
            scopesSupported: ['mcp:tools'],
        }),
    );
    return { app, provider, model };
}

describe('generateDeviceUserCode', () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('formats the code as XXXX-XXXX from the wearable alphabet', () => {
        for (let i = 0; i < 200; i++) {
            expect(generateDeviceUserCode()).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ2-9]{4}-[BCDFGHJKLMNPQRSTVWXZ2-9]{4}$/);
        }
    });

    it('normalizes back to the eight characters it generated', () => {
        const code = generateDeviceUserCode();

        expect(normalizeDeviceUserCode(code)).toBe(code.replace('-', ''));
        expect(normalizeDeviceUserCode(code.toLowerCase())).toBe(code.replace('-', ''));
    });

    /**
     * The alphabet's length does not divide 256, so deriving each character by reducing a random
     * byte would over-represent the first `256 % length` of them. Asserting that a uniform index
     * is drawn per character pins that, where a distribution test could only ever be statistical.
     */
    it('draws a uniform index per character instead of reducing a byte', () => {
        const randomInt = vi.spyOn(crypto, 'randomInt');
        const randomBytes = vi.spyOn(crypto, 'randomBytes');

        generateDeviceUserCode();

        expect(randomInt).toHaveBeenCalledTimes(8);
        // Every draw covers the whole alphabet, so no character is reachable by more paths than
        // another. 28 today; the assertion is that all eight draws share one range.
        const ranges = new Set(randomInt.mock.calls.map((call) => call[0]));
        expect(ranges.size).toBe(1);
        expect(randomBytes).not.toHaveBeenCalled();
    });
});

describe('RFC 8628 device authorization grant', () => {
    it('advertises device_authorization_endpoint and grant type in metadata', async () => {
        const { app } = createDeviceFlowApp();
        const res = await supertest(app).get('/.well-known/oauth-authorization-server');
        expect(res.status).toBe(200);
        expect(res.body.grant_types_supported).toContain(DEVICE_AUTHORIZATION_GRANT_TYPE);
        expect(res.body.device_authorization_endpoint).toBe('http://127.0.0.1/device');
    });

    it('issues codes from /device and returns tokens after approval', async () => {
        const { app, provider } = createDeviceFlowApp();

        const reg = await supertest(app)
            .post('/register')
            .send({
                redirect_uris: ['http://localhost/cb'],
                grant_types: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
                response_types: ['code'],
                token_endpoint_auth_method: 'none',
            });
        expect(reg.status).toBe(201);
        const clientId = reg.body.client_id as string;

        const dev = await supertest(app).post('/device').type('form').send({
            client_id: clientId,
            scope: 'mcp:tools',
        });
        expect(dev.status).toBe(200);
        expect(dev.body.device_code).toBeTruthy();
        expect(dev.body.user_code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/i);
        expect(dev.body.verification_uri).toBe('http://127.0.0.1/device');
        expect(dev.body.verification_uri_complete).toContain('user_code=');
        expect(dev.body.expires_in).toBe(900);
        expect(dev.body.interval).toBe(5);

        const pollPending = await supertest(app).post('/token').type('form').send({
            client_id: clientId,
            grant_type: DEVICE_AUTHORIZATION_GRANT_TYPE,
            device_code: dev.body.device_code,
        });
        expect(pollPending.status).toBe(400);
        expect(pollPending.body.error).toBe('authorization_pending');

        await provider.approveDeviceAuthorization(dev.body.user_code, 'user-42');

        const pollOk = await supertest(app).post('/token').type('form').send({
            client_id: clientId,
            grant_type: DEVICE_AUTHORIZATION_GRANT_TYPE,
            device_code: dev.body.device_code,
        });
        expect(pollOk.status).toBe(200);
        expect(pollOk.body.access_token).toBeTruthy();
        expect(pollOk.body.refresh_token).toBeTruthy();
        expect(pollOk.body.token_type).toBe('bearer');
    });

    it('returns slow_down when polling faster than the interval', async () => {
        const { app, provider } = createDeviceFlowApp();

        const reg = await supertest(app)
            .post('/register')
            .send({
                redirect_uris: ['http://localhost/cb'],
                grant_types: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
                response_types: ['code'],
                token_endpoint_auth_method: 'none',
            });
        expect(reg.status).toBe(201);

        const dev = await supertest(app).post('/device').type('form').send({
            client_id: reg.body.client_id,
        });
        expect(dev.status).toBe(200);

        const body = {
            client_id: reg.body.client_id,
            grant_type: DEVICE_AUTHORIZATION_GRANT_TYPE,
            device_code: dev.body.device_code,
        };

        const first = await supertest(app).post('/token').type('form').send(body);
        expect(first.body.error).toBe('authorization_pending');

        const second = await supertest(app).post('/token').type('form').send(body);
        expect(second.status).toBe(400);
        expect(second.body.error).toBe('slow_down');

        await provider.approveDeviceAuthorization(dev.body.user_code, 'u1');
    });

    it('binds device-flow tokens to one grant so revocation cascades', async () => {
        const { app, provider, model } = createDeviceFlowApp();

        const reg = await supertest(app)
            .post('/register')
            .send({
                redirect_uris: ['http://localhost/cb'],
                grant_types: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
                response_types: ['code'],
                token_endpoint_auth_method: 'none',
            });
        const clientId = reg.body.client_id as string;

        const dev = await supertest(app).post('/device').type('form').send({ client_id: clientId, scope: 'mcp:tools' });
        await provider.approveDeviceAuthorization(dev.body.user_code, 'user-42');

        const tokens = await supertest(app).post('/token').type('form').send({
            client_id: clientId,
            grant_type: DEVICE_AUTHORIZATION_GRANT_TYPE,
            device_code: dev.body.device_code,
        });
        expect(tokens.status).toBe(200);

        const accessToken = await model.getAccessToken(tokens.body.access_token);
        expect(accessToken!.grantId).toBeTruthy();

        // RFC 7009 §2.1 cascade, reached through the device grant rather than a code exchange.
        const revoked = await supertest(app).post('/revoke').type('form').send({
            client_id: clientId,
            token: tokens.body.refresh_token,
        });
        expect(revoked.status).toBe(200);
        expect(await model.getAccessToken(tokens.body.access_token)).toBeUndefined();
    });

    it('returns access_denied after denyDeviceAuthorization', async () => {
        const { app, provider } = createDeviceFlowApp();

        const reg = await supertest(app)
            .post('/register')
            .send({
                redirect_uris: ['http://localhost/cb'],
                grant_types: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
                response_types: ['code'],
                token_endpoint_auth_method: 'none',
            });
        expect(reg.status).toBe(201);

        const dev = await supertest(app).post('/device').type('form').send({
            client_id: reg.body.client_id,
        });
        expect(dev.status).toBe(200);

        await provider.denyDeviceAuthorization(dev.body.user_code);

        const poll = await supertest(app).post('/token').type('form').send({
            client_id: reg.body.client_id,
            grant_type: DEVICE_AUTHORIZATION_GRANT_TYPE,
            device_code: dev.body.device_code,
        });
        expect(poll.status).toBe(400);
        expect(poll.body.error).toBe('access_denied');
    });
});
