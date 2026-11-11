import { describe, it, expect, beforeEach } from 'vitest';
import express from 'express';
import supertest from 'supertest';
import { parseScope } from '../scope.js';
import { OAuthServer } from '../OAuthServer.js';
import { mcpAuthRouter } from '../router.js';
import { authenticateHandler } from '../handlers/authenticate.js';
import { generatePKCEPair } from './test-helpers.js';

describe('parseScope', () => {
    it('returns undefined when the parameter is absent', () => {
        expect(parseScope(undefined)).toBeUndefined();
    });

    it('returns undefined when the parameter holds no scope tokens', () => {
        expect(parseScope('')).toBeUndefined();
        expect(parseScope('   ')).toBeUndefined();
    });

    it('splits on any run of whitespace', () => {
        expect(parseScope('a b')).toEqual(['a', 'b']);
        expect(parseScope(' a  b\tc ')).toEqual(['a', 'b', 'c']);
    });
});

describe('default scopes through the authorization code flow', () => {
    const resource = 'https://rs.example.com/mcp';
    let app: express.Express;
    let clientId: string;

    beforeEach(async () => {
        const provider = new OAuthServer({
            issuerUrl: new URL('https://as.example.com/'),
            authorizationUrl: new URL('https://as.example.com/consent'),
            resourceServerUrl: new URL(resource),
            scopesSupported: ['mcp:tools', 'mcp:resources'],
        });

        app = express();
        app.use(mcpAuthRouter({ provider }));
        app.use('/confirm', authenticateHandler({ provider, getUser: () => 'user-1' }));

        const registration = await supertest(app)
            .post('/register')
            .send({
                redirect_uris: ['https://client.example/callback'],
                token_endpoint_auth_method: 'none',
                grant_types: ['authorization_code', 'refresh_token'],
            });
        clientId = registration.body.client_id;
    });

    const exchange = async (scope?: string) => {
        const { codeVerifier, codeChallenge } = generatePKCEPair();
        const params = {
            client_id: clientId,
            response_type: 'code',
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            resource,
            ...(scope === undefined ? {} : { scope }),
        };

        const authorize = await supertest(app).get('/authorize').query(params);
        const consentUrl = new URL(authorize.headers.location);

        const confirm = await supertest(app).post('/confirm').type('form').send(params);
        const code = new URL(confirm.headers.location).searchParams.get('code');

        const token = await supertest(app)
            .post('/token')
            .type('form')
            .send({ grant_type: 'authorization_code', client_id: clientId, code, code_verifier: codeVerifier, resource });

        return { consentScope: consentUrl.searchParams.get('scope'), tokenScope: token.body.scope };
    };

    it('grants every supported scope when the client sends none', async () => {
        expect(await exchange()).toEqual({ consentScope: 'mcp:tools mcp:resources', tokenScope: 'mcp:tools mcp:resources' });
    });

    it('treats an empty scope parameter as none sent', async () => {
        expect(await exchange('')).toEqual({ consentScope: 'mcp:tools mcp:resources', tokenScope: 'mcp:tools mcp:resources' });
    });

    it('grants only what was requested when the client sends a scope', async () => {
        expect(await exchange('mcp:tools')).toEqual({ consentScope: 'mcp:tools', tokenScope: 'mcp:tools' });
    });
});
