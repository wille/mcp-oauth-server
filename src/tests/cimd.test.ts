import { describe, it, expect, vi, afterEach } from 'vitest';
import express from 'express';
import supertest from 'supertest';
import { ClientIdMetadataDocumentFetcher, isClientIdMetadataDocumentUrl } from '../cimd.js';
import { InvalidClientError } from '../errors.js';
import { OAuthServer } from '../OAuthServer.js';
import { MemoryOAuthServerModel } from '../MemoryOAuthServerModel.js';
import { mcpAuthRouter } from '../router.js';
import { authorizationHandler } from '../handlers/authorize.js';

const CLIENT_ID = 'https://app.example.com/oauth/client.json';

const validDocument = {
    client_id: CLIENT_ID,
    client_name: 'Example MCP Client',
    redirect_uris: ['https://app.example.com/callback'],
    grant_types: ['authorization_code'],
    token_endpoint_auth_method: 'none',
};

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
        ...init,
    });
}

function mockFetch(body: unknown, init: ResponseInit = {}) {
    return vi.fn(async () => jsonResponse(body, init)) as unknown as typeof fetch & ReturnType<typeof vi.fn>;
}

describe('isClientIdMetadataDocumentUrl', () => {
    it('accepts an HTTPS URL with a path component', () => {
        expect(isClientIdMetadataDocumentUrl(CLIENT_ID)).toBe(true);
    });

    it('rejects http URLs', () => {
        expect(isClientIdMetadataDocumentUrl('http://app.example.com/client.json')).toBe(false);
    });

    it('rejects URLs without a path component', () => {
        expect(isClientIdMetadataDocumentUrl('https://app.example.com')).toBe(false);
        expect(isClientIdMetadataDocumentUrl('https://app.example.com/')).toBe(false);
    });

    it('rejects URLs with a fragment', () => {
        expect(isClientIdMetadataDocumentUrl('https://app.example.com/client.json#frag')).toBe(false);
    });

    it('rejects URLs with credentials', () => {
        expect(isClientIdMetadataDocumentUrl('https://user:pass@app.example.com/client.json')).toBe(false);
    });

    it('rejects plain client ids', () => {
        expect(isClientIdMetadataDocumentUrl('d36259ef-6881-4587-bee4-f6451853d812')).toBe(false);
    });
});

describe('ClientIdMetadataDocumentFetcher', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    it('fetches and validates a client metadata document', async () => {
        const fetch = mockFetch(validDocument);
        const fetcher = new ClientIdMetadataDocumentFetcher({ fetch });

        const { client, expiresAt } = await fetcher.fetchClient(CLIENT_ID);

        expect(client.client_id).toBe(CLIENT_ID);
        expect(client.client_name).toBe('Example MCP Client');
        expect(client.redirect_uris).toEqual(['https://app.example.com/callback']);
        expect(expiresAt.getTime()).toBeGreaterThan(Date.now());
        expect(fetch).toHaveBeenCalledWith(
            CLIENT_ID,
            expect.objectContaining({ redirect: 'error', headers: { accept: 'application/json' } }),
        );
    });

    it('returns an already-expired document when the response forbids caching', async () => {
        const fetch = vi.fn(async () =>
            jsonResponse(validDocument, { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } }),
        ) as unknown as typeof fetch & ReturnType<typeof vi.fn>;
        const fetcher = new ClientIdMetadataDocumentFetcher({ fetch });

        const { expiresAt } = await fetcher.fetchClient(CLIENT_ID);

        expect(expiresAt.getTime()).toBeLessThanOrEqual(Date.now());
    });

    it('rejects a document whose client_id does not match the URL', async () => {
        const fetch = mockFetch({ ...validDocument, client_id: 'https://evil.example.com/client.json' });
        const fetcher = new ClientIdMetadataDocumentFetcher({ fetch });

        await expect(fetcher.fetchClient(CLIENT_ID)).rejects.toThrow(InvalidClientError);
    });

    it('rejects a document without client_name', async () => {
        const { client_name: _, ...withoutName } = validDocument;
        const fetcher = new ClientIdMetadataDocumentFetcher({ fetch: mockFetch(withoutName) });

        await expect(fetcher.fetchClient(CLIENT_ID)).rejects.toThrow(InvalidClientError);
    });

    it('rejects a document without redirect_uris', async () => {
        const fetcher = new ClientIdMetadataDocumentFetcher({ fetch: mockFetch({ ...validDocument, redirect_uris: [] }) });

        await expect(fetcher.fetchClient(CLIENT_ID)).rejects.toThrow(InvalidClientError);
    });

    it('rejects a document that is not valid JSON', async () => {
        const fetcher = new ClientIdMetadataDocumentFetcher({ fetch: mockFetch('not json') });

        await expect(fetcher.fetchClient(CLIENT_ID)).rejects.toThrow('client_id metadata document is not valid JSON');
    });

    it('rejects non-OK responses', async () => {
        const fetcher = new ClientIdMetadataDocumentFetcher({ fetch: mockFetch('missing', { status: 404 }) });

        await expect(fetcher.fetchClient(CLIENT_ID)).rejects.toThrow('HTTP 404');
    });

    it('rejects oversized documents', async () => {
        const fetcher = new ClientIdMetadataDocumentFetcher({
            fetch: mockFetch({ ...validDocument, client_uri: 'https://app.example.com/' + 'x'.repeat(10 * 1024) }),
        });

        await expect(fetcher.fetchClient(CLIENT_ID)).rejects.toThrow('too large');
    });

    it('rejects loopback and IP-literal hosts without fetching', async () => {
        const fetch = mockFetch(validDocument);
        const fetcher = new ClientIdMetadataDocumentFetcher({ fetch });

        await expect(fetcher.fetchClient('https://localhost/client.json')).rejects.toThrow('host is not allowed');
        await expect(fetcher.fetchClient('https://app.localhost/client.json')).rejects.toThrow('host is not allowed');
        await expect(fetcher.fetchClient('https://192.168.1.1/client.json')).rejects.toThrow('host is not allowed');
        await expect(fetcher.fetchClient('https://[::1]/client.json')).rejects.toThrow('host is not allowed');
        expect(fetch).not.toHaveBeenCalled();
    });

    it('rejects URLs failing the trust policy hook', async () => {
        const fetch = mockFetch(validDocument);
        const fetcher = new ClientIdMetadataDocumentFetcher({
            fetch,
            validateClientIdUrl: (url) => url.hostname.endsWith('.trusted.example'),
        });

        await expect(fetcher.fetchClient(CLIENT_ID)).rejects.toThrow('not trusted');
        expect(fetch).not.toHaveBeenCalled();
    });
});

describe('OAuthServer CIMD integration', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    function createServer(document: unknown, options: { grantTypes?: any[]; model?: MemoryOAuthServerModel; fetch?: typeof fetch } = {}) {
        const fetch = options.fetch ?? mockFetch(document);
        const model = options.model ?? new MemoryOAuthServerModel();
        const server = new OAuthServer({
            model,
            issuerUrl: new URL('https://auth.example.com'),
            authorizationUrl: new URL('https://auth.example.com/consent'),
            scopesSupported: ['mcp:tools'],
            grantTypes: options.grantTypes,
            clientIdMetadataDocuments: { fetch },
        });
        return { server, model, fetch };
    }

    it('resolves URL client_ids through getClient', async () => {
        const { server } = createServer(validDocument);

        const client = await server.getClient(CLIENT_ID);
        expect(client?.client_id).toBe(CLIENT_ID);
        expect(client?.client_secret).toBeUndefined();
    });

    it('rejects documents requiring client secret authentication', async () => {
        const { server } = createServer({ ...validDocument, token_endpoint_auth_method: 'client_secret_post' });

        await expect(server.getClient(CLIENT_ID)).rejects.toThrow('Unsupported token_endpoint_auth_method');
    });

    it('rejects documents requesting grants the server has not enabled', async () => {
        const { server } = createServer({ ...validDocument, grant_types: ['authorization_code', 'client_credentials'] });

        await expect(server.getClient(CLIENT_ID)).rejects.toThrow('Unsupported grant_type');
    });

    it('falls through to the model when CIMD is disabled', async () => {
        const server = new OAuthServer({
            model: new MemoryOAuthServerModel(),
            authorizationUrl: new URL('https://auth.example.com/consent'),
        });

        await expect(server.getClient(CLIENT_ID)).resolves.toBeUndefined();
    });

    it('throws at construction when CIMD is enabled but the model lacks the cache methods', () => {
        const bareModel = {
            getClient: async () => undefined,
            saveAccessToken: async () => {},
            getAccessToken: async () => undefined,
            revokeAccessToken: async () => {},
            saveRefreshToken: async () => {},
            getRefreshToken: async () => undefined,
            revokeRefreshToken: async () => {},
            saveAuthorizationCode: async () => {},
            getAuthorizationCode: async () => undefined,
            revokeAuthorizationCode: async () => {},
        };

        expect(
            () =>
                new OAuthServer({
                    model: bareModel as any,
                    authorizationUrl: new URL('https://auth.example.com/consent'),
                    dynamicClientRegistration: false,
                    clientIdMetadataDocuments: true,
                }),
        ).toThrow('clientIdMetadataDocuments requires OAuthServerModel methods');
    });

    it('caches fetched documents in the model', async () => {
        const { server, model, fetch } = createServer(validDocument);

        await server.getClient(CLIENT_ID);
        await server.getClient(CLIENT_ID);

        expect(fetch).toHaveBeenCalledTimes(1);
        const cached = await model.getClientIdMetadataDocument(CLIENT_ID);
        expect(cached?.client.client_id).toBe(CLIENT_ID);
        expect(cached?.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    it('shares the cache between server instances using the same model', async () => {
        const model = new MemoryOAuthServerModel();
        const fetch = mockFetch(validDocument);
        const { server: serverA } = createServer(validDocument, { model, fetch });
        const { server: serverB } = createServer(validDocument, { model, fetch });

        await serverA.getClient(CLIENT_ID);
        await serverB.getClient(CLIENT_ID);

        expect(fetch).toHaveBeenCalledTimes(1);
    });

    it('does not cache documents served with Cache-Control: no-store', async () => {
        const fetch = vi.fn(async () =>
            jsonResponse(validDocument, { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } }),
        ) as unknown as typeof fetch & ReturnType<typeof vi.fn>;
        const { server, model } = createServer(validDocument, { fetch });

        await server.getClient(CLIENT_ID);
        await server.getClient(CLIENT_ID);

        expect(fetch).toHaveBeenCalledTimes(2);
        await expect(model.getClientIdMetadataDocument(CLIENT_ID)).resolves.toBeUndefined();
    });

    it('re-fetches documents after Cache-Control max-age expires', async () => {
        vi.useFakeTimers();
        const fetch = vi.fn(async () =>
            jsonResponse(validDocument, { headers: { 'content-type': 'application/json', 'cache-control': 'max-age=60' } }),
        ) as unknown as typeof fetch & ReturnType<typeof vi.fn>;
        const { server } = createServer(validDocument, { fetch });

        await server.getClient(CLIENT_ID);
        vi.advanceTimersByTime(30 * 1000);
        await server.getClient(CLIENT_ID);
        expect(fetch).toHaveBeenCalledTimes(1);

        vi.advanceTimersByTime(31 * 1000);
        await server.getClient(CLIENT_ID);
        expect(fetch).toHaveBeenCalledTimes(2);
    });

    it('completes an authorization request with a URL client_id', async () => {
        const { server } = createServer(validDocument);
        const app = express();
        app.use('/authorize', authorizationHandler({ provider: server }));

        const response = await supertest(app).get('/authorize').query({
            client_id: CLIENT_ID,
            redirect_uri: 'https://app.example.com/callback',
            response_type: 'code',
            code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            code_challenge_method: 'S256',
            resource: 'https://auth.example.com/mcp',
        });

        expect(response.status).toBe(302);
        const location = new URL(response.header.location);
        expect(location.pathname).toBe('/consent');
        expect(location.searchParams.get('client_id')).toBe(CLIENT_ID);
    });
});

describe('CIMD metadata advertisement', () => {
    function metadataApp(clientIdMetadataDocuments: boolean) {
        const server = new OAuthServer({
            model: new MemoryOAuthServerModel(),
            issuerUrl: new URL('https://auth.example.com'),
            authorizationUrl: new URL('https://auth.example.com/consent'),
            clientIdMetadataDocuments: clientIdMetadataDocuments ? { fetch: mockFetch(validDocument) } : undefined,
        });
        const app = express();
        app.use(mcpAuthRouter({ provider: server }));
        return app;
    }

    it('advertises client_id_metadata_document_supported when enabled', async () => {
        const response = await supertest(metadataApp(true)).get('/.well-known/oauth-authorization-server');

        expect(response.status).toBe(200);
        expect(response.body.client_id_metadata_document_supported).toBe(true);
    });

    it('omits client_id_metadata_document_supported when disabled', async () => {
        const response = await supertest(metadataApp(false)).get('/.well-known/oauth-authorization-server');

        expect(response.status).toBe(200);
        expect(response.body.client_id_metadata_document_supported).toBeUndefined();
    });
});
