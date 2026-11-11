import { describe, it, expect } from 'vitest';
import express from 'express';
import supertest from 'supertest';
import { OAuthServer } from '../OAuthServer.js';
import { MemoryOAuthServerModel } from '../MemoryOAuthServerModel.js';
import { DEVICE_AUTHORIZATION_GRANT_TYPE } from '../deviceFlow.js';
import { InvalidTokenError } from '../errors.js';
import { requireBearerAuth } from '../middleware/bearerAuth.js';
import { authenticateHandler } from '../handlers/authenticate.js';
import { approveDeviceAuthorizationHandler } from '../handlers/approveDeviceAuthorization.js';
import { createTestClient, TEST_CODE_CHALLENGE } from './test-helpers.js';

describe('requireBearerAuth answers 401 for a token that is no longer acceptable', () => {
    const resource = 'https://rs.example.com/mcp';

    async function appFor(serverOptions: { scopesSupported: string[]; resourceServerUrl: string }) {
        const model = new MemoryOAuthServerModel();
        await model.saveAccessToken(
            {
                token: 'stored-token',
                clientId: 'client',
                scopes: ['mcp:tools', 'mcp:legacy'],
                expiresAt: new Date(Date.now() + 60_000),
                resource,
            },
            createTestClient(),
        );
        const verifier = new OAuthServer({
            model,
            authorizationUrl: new URL('https://as.example.com/consent'),
            scopesSupported: serverOptions.scopesSupported,
            resourceServerUrl: new URL(serverOptions.resourceServerUrl),
        });

        const app = express();
        app.get('/mcp', requireBearerAuth({ verifier }), (_req, res) => {
            res.json({ ok: true });
        });
        return app;
    }

    const get = (app: express.Express) => supertest(app).get('/mcp').set('Authorization', 'Bearer stored-token');

    it('accepts the token while its scopes and resource are still valid', async () => {
        const app = await appFor({ scopesSupported: ['mcp:tools', 'mcp:legacy'], resourceServerUrl: resource });
        expect((await get(app)).status).toBe(200);
    });

    it('when one of its scopes has been removed from scopesSupported', async () => {
        const app = await appFor({ scopesSupported: ['mcp:tools'], resourceServerUrl: resource });
        const response = await get(app);

        expect(response.status).toBe(401);
        expect(response.body.error).toBe('invalid_token');
        expect(response.headers['www-authenticate']).toContain('error="invalid_token"');
    });

    it('when the resource server URL no longer matches', async () => {
        const app = await appFor({ scopesSupported: ['mcp:tools', 'mcp:legacy'], resourceServerUrl: 'https://other.example.com/mcp' });
        const response = await get(app);

        expect(response.status).toBe(401);
        expect(response.body.error).toBe('invalid_token');
    });
});

describe('requireBearerAuth WWW-Authenticate quoting', () => {
    it('escapes quotes and backslashes and flattens line breaks in a verifier message', async () => {
        const app = express();
        app.get(
            '/mcp',
            requireBearerAuth({
                verifier: {
                    verifyAccessToken: async () => {
                        throw new InvalidTokenError('bad "token", realm="evil"\r\nX-Injected: 1 \\');
                    },
                },
            }),
        );

        const response = await supertest(app).get('/mcp').set('Authorization', 'Bearer anything');

        expect(response.status).toBe(401);
        expect(response.headers['x-injected']).toBeUndefined();
        expect(response.headers['www-authenticate']).toBe(
            'Bearer error="invalid_token", error_description="bad \\"token\\", realm=\\"evil\\" X-Injected: 1 \\\\"',
        );
    });
});

describe('handlers answer 401 when nobody is signed in', () => {
    const provider = new OAuthServer({
        authorizationUrl: new URL('https://as.example.com/consent'),
        deviceAuthorizationUrl: new URL('https://as.example.com/device'),
        grantTypes: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
        strictResource: false,
    });
    const client = createTestClient({ redirect_uris: ['https://client.example/callback'] });

    it('authenticateHandler', async () => {
        await provider.model.registerClient!(client);
        const app = express();
        app.use('/confirm', authenticateHandler({ provider, getUser: () => '' }));

        const response = await supertest(app).post('/confirm').type('form').send({
            client_id: client.client_id,
            response_type: 'code',
            code_challenge: TEST_CODE_CHALLENGE,
            code_challenge_method: 'S256',
        });

        expect(response.status).toBe(401);
        expect(response.body.error).toBe('access_denied');
        expect(response.headers.location).toBeUndefined();
    });

    it('approveDeviceAuthorizationHandler', async () => {
        const app = express();
        app.use('/approve', approveDeviceAuthorizationHandler({ provider, getUser: () => '' }));

        const response = await supertest(app).post('/approve').type('form').send({ user_code: 'BCDF-GHJK' });

        expect(response.status).toBe(401);
        expect(response.body.error).toBe('access_denied');
    });
});
