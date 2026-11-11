import { describe, it, expect, beforeEach } from 'vitest';
import express from 'express';
import supertest from 'supertest';
import { OAuthServer } from '../../OAuthServer.js';
import { DEVICE_AUTHORIZATION_GRANT_TYPE } from '../../deviceFlow.js';
import { tokenHandler, TokenHandlerOptions } from '../../handlers/token.js';
import { createTestClient } from '../test-helpers.js';

describe('Token handler rate limiting', () => {
    const client = createTestClient({ grant_types: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE] });
    let provider: OAuthServer;

    beforeEach(async () => {
        provider = new OAuthServer({
            authorizationUrl: new URL('https://as.example.com/consent'),
            deviceAuthorizationUrl: new URL('https://as.example.com/device'),
            grantTypes: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
            strictResource: false,
        });
        await provider.model.registerClient!(client);
    });

    const appWith = (options: Omit<TokenHandlerOptions, 'provider'> = {}) => {
        const app = express();
        app.use('/token', tokenHandler({ provider, ...options }));
        return app;
    };

    const poll = (app: express.Express, deviceCode: string) =>
        supertest(app)
            .post('/token')
            .type('form')
            .send({ grant_type: DEVICE_AUTHORIZATION_GRANT_TYPE, client_id: client.client_id, device_code: deviceCode });

    const refresh = (app: express.Express) =>
        supertest(app)
            .post('/token')
            .type('form')
            .send({ grant_type: 'refresh_token', client_id: client.client_id, refresh_token: 'nope' });

    it('lets a device poll at the advertised interval for the whole lifetime of its code', async () => {
        const app = appWith();
        const device = await provider.requestDeviceAuthorization(client, {});
        const polls = Math.ceil(device.expires_in / device.interval);
        expect(polls).toBeGreaterThan(50);

        for (let i = 0; i < polls; i++) {
            const response = await poll(app, device.device_code);
            expect(response.status).not.toBe(429);
        }
    });

    it('does not count device polls against the general token limit', async () => {
        const app = appWith({ rateLimit: { max: 2 } });
        const device = await provider.requestDeviceAuthorization(client, {});

        for (let i = 0; i < 10; i++) {
            expect((await poll(app, device.device_code)).status).not.toBe(429);
        }

        expect((await refresh(app)).status).toBe(400);
        expect((await refresh(app)).status).toBe(400);
        expect((await refresh(app)).status).toBe(429);
    });

    it('still limits device polls, on their own budget', async () => {
        const app = appWith({ devicePollRateLimit: { max: 3 } });
        const device = await provider.requestDeviceAuthorization(client, {});

        for (let i = 0; i < 3; i++) {
            expect((await poll(app, device.device_code)).status).not.toBe(429);
        }
        const limited = await poll(app, device.device_code);
        expect(limited.status).toBe(429);
        expect(limited.body.error).toBe('too_many_requests');

        // The general budget is untouched.
        expect((await refresh(app)).status).toBe(400);
    });

    it('sizes the default device budget from the poll interval', async () => {
        provider.devicePollIntervalSeconds = 300; // 3 polls per 15 minutes, so a budget of 6
        const app = appWith();
        const device = await provider.requestDeviceAuthorization(client, {});

        for (let i = 0; i < 6; i++) {
            expect((await poll(app, device.device_code)).status).not.toBe(429);
        }
        expect((await poll(app, device.device_code)).status).toBe(429);
    });

    it('keeps a caller-supplied skip on the general limiter', async () => {
        const app = appWith({ rateLimit: { max: 1, skip: () => true } });

        expect((await refresh(app)).status).toBe(400);
        expect((await refresh(app)).status).toBe(400);
    });

    it('disables both limiters with rateLimit: false', async () => {
        provider.devicePollIntervalSeconds = 900; // a default budget of 2
        const app = appWith({ rateLimit: false });
        const device = await provider.requestDeviceAuthorization(client, {});

        for (let i = 0; i < 5; i++) {
            expect((await poll(app, device.device_code)).status).not.toBe(429);
        }
    });
});
