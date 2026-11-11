import { describe, it, expect } from 'vitest';
import * as z from 'zod/v4';
import express from 'express';
import supertest from 'supertest';
import { describeValidationError } from '../validation.js';
import { OAuthServer } from '../OAuthServer.js';
import { mcpAuthRouter } from '../router.js';

// RFC 6749 §5.2: error_description is limited to %x20-21 / %x23-5B / %x5D-7E.
const ALLOWED_IN_ERROR_DESCRIPTION = /^[\x20-\x21\x23-\x5b\x5d-\x7e]*$/;

describe('describeValidationError', () => {
    const schema = z.object({ response_type: z.literal('code'), code_challenge: z.string() });

    it('names each offending parameter on one line', () => {
        const result = schema.safeParse({ response_type: 'token' });
        expect(result.success).toBe(false);

        const description = describeValidationError(result.error!);
        expect(description).toBe(
            "response_type: Invalid input: expected 'code'; code_challenge: Invalid input: expected string, received undefined",
        );
        expect(description).toMatch(ALLOWED_IN_ERROR_DESCRIPTION);
    });

    it('describes a missing body without a path', () => {
        const description = describeValidationError(schema.safeParse(undefined).error!);
        expect(description).toContain('expected object');
        expect(description).toMatch(ALLOWED_IN_ERROR_DESCRIPTION);
    });
});

describe('error_description on the wire', () => {
    const provider = new OAuthServer({
        issuerUrl: new URL('https://as.example.com/'),
        authorizationUrl: new URL('https://as.example.com/consent'),
    });
    const app = express();
    app.use(mcpAuthRouter({ provider }));

    it('is a single readable line in an authorization error redirect', async () => {
        const registration = await supertest(app)
            .post('/register')
            .send({ redirect_uris: ['https://client.example/callback'], token_endpoint_auth_method: 'none' });

        const response = await supertest(app).get('/authorize').query({ client_id: registration.body.client_id });
        const redirect = new URL(response.headers.location);

        expect(redirect.searchParams.get('error')).toBe('invalid_request');
        expect(redirect.searchParams.get('error_description')).toMatch(/^response_type: /);
        expect(redirect.searchParams.get('error_description')).toMatch(ALLOWED_IN_ERROR_DESCRIPTION);
    });

    it('is a single readable line in a token error response', async () => {
        const response = await supertest(app).post('/token').type('form').send({ grant_type: 'authorization_code' });

        expect(response.status).toBe(400);
        expect(response.body.error_description).toMatch(/^client_id: /);
        expect(response.body.error_description).toMatch(ALLOWED_IN_ERROR_DESCRIPTION);
    });
});

describe('PKCE parameter format (RFC 7636)', () => {
    const provider = new OAuthServer({
        issuerUrl: new URL('https://as.example.com/'),
        authorizationUrl: new URL('https://as.example.com/consent'),
        strictResource: false,
    });
    const app = express();
    app.use(mcpAuthRouter({ provider }));

    const register = async () =>
        (
            await supertest(app)
                .post('/register')
                .send({ redirect_uris: ['https://client.example/callback'], token_endpoint_auth_method: 'none' })
        ).body.client_id as string;

    const authorize = async (codeChallenge: string) => {
        const response = await supertest(app)
            .get('/authorize')
            .query({
                client_id: await register(),
                response_type: 'code',
                code_challenge: codeChallenge,
                code_challenge_method: 'S256',
            });
        return new URL(response.headers.location);
    };

    it('accepts a 43-character base64url code_challenge', async () => {
        const redirect = await authorize('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
        expect(redirect.origin + redirect.pathname).toBe('https://as.example.com/consent');
    });

    it.each([
        ['too short', 'challenge123'],
        ['padded', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM='],
        ['standard base64 alphabet', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM'],
        ['empty', ''],
    ])('rejects a %s code_challenge before the consent screen', async (_name, challenge) => {
        const redirect = await authorize(challenge);

        expect(redirect.origin).toBe('https://client.example');
        expect(redirect.searchParams.get('error')).toBe('invalid_request');
        expect(redirect.searchParams.get('error_description')).toContain('code_challenge');
    });

    it.each([
        ['shorter than 43 characters', 'short'],
        ['longer than 128 characters', 'a'.repeat(129)],
        ['containing characters outside the unreserved set', `${'a'.repeat(43)}+/`],
    ])('rejects a code_verifier %s', async (_name, verifier) => {
        const response = await supertest(app)
            .post('/token')
            .type('form')
            .send({ grant_type: 'authorization_code', client_id: await register(), code: 'any', code_verifier: verifier });

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('invalid_request');
        expect(response.body.error_description).toContain('code_verifier');
        expect(response.body.error_description).toMatch(ALLOWED_IN_ERROR_DESCRIPTION);
    });
});
