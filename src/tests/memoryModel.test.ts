import { describe, it, expect, vi, afterEach } from 'vitest';
import { MemoryOAuthServerModel } from '../MemoryOAuthServerModel.js';
import { OAuthServer } from '../OAuthServer.js';
import { createTestClient } from './test-helpers.js';

describe('MemoryOAuthServerModel expiry sweep', () => {
    const client = createTestClient();
    const past = () => new Date(Date.now() - 1000);
    const future = () => new Date(Date.now() + 60 * 60 * 1000);

    afterEach(() => {
        vi.useRealTimers();
    });

    async function seed(model: MemoryOAuthServerModel, expiresAt: () => Date, suffix: string) {
        await model.saveAccessToken({ token: `access-${suffix}`, clientId: client.client_id, scopes: [], expiresAt: expiresAt() }, client);
        await model.saveRefreshToken(
            { token: `refresh-${suffix}`, clientId: client.client_id, scopes: [], expiresAt: expiresAt() },
            client,
        );
        await model.saveAuthorizationCode({
            authorizationCode: `code-${suffix}`,
            clientId: client.client_id,
            userId: 'user-1',
            codeChallenge: 'challenge',
            redirectUri: client.redirect_uris[0],
            expiresAt: expiresAt(),
        });
        await model.saveDeviceAuthorization({
            deviceCode: `device-${suffix}`,
            userCode: `${suffix.toUpperCase().padEnd(4, 'X').slice(0, 4)}-BCDF`,
            clientId: client.client_id,
            scopes: [],
            expiresAt: expiresAt(),
            pollIntervalSeconds: 5,
            status: 'pending',
        });
        await model.saveClientIdMetadataDocument({
            client: { ...client, client_id: `https://client.example/${suffix}.json` },
            expiresAt: expiresAt(),
        });
    }

    it('purgeExpired removes expired records of every kind and keeps live ones', async () => {
        const model = new MemoryOAuthServerModel();
        await seed(model, past, 'old');
        await seed(model, future, 'new');

        expect(model.purgeExpired()).toBe(5);

        expect(await model.getAccessToken('access-old')).toBeUndefined();
        expect(await model.getRefreshToken('refresh-old')).toBeUndefined();
        expect(await model.getAuthorizationCode('code-old')).toBeUndefined();
        expect(await model.getDeviceAuthorizationByDeviceCode('device-old')).toBeUndefined();
        expect(await model.getDeviceAuthorizationByUserCode('OLDXBCDF')).toBeUndefined();
        expect(await model.getClientIdMetadataDocument('https://client.example/old.json')).toBeUndefined();

        expect(await model.getAccessToken('access-new')).toBeDefined();
        expect(await model.getRefreshToken('refresh-new')).toBeDefined();
        expect(await model.getAuthorizationCode('code-new')).toBeDefined();
        expect(await model.getDeviceAuthorizationByUserCode('NEWXBCDF')).toBeDefined();
        expect(await model.getClientIdMetadataDocument('https://client.example/new.json')).toBeDefined();
    });

    it('never removes registered clients', async () => {
        const model = new MemoryOAuthServerModel();
        await model.registerClient(client);

        model.purgeExpired(new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000));

        expect(await model.getClient(client.client_id)).toBeDefined();
    });

    it('sweeps by itself on a later write', async () => {
        vi.useFakeTimers();
        const model = new MemoryOAuthServerModel();
        await model.saveAccessToken(
            { token: 'short-lived', clientId: client.client_id, scopes: [], expiresAt: new Date(Date.now() + 1000) },
            client,
        );

        vi.advanceTimersByTime(2 * 60 * 1000);
        await model.saveAccessToken({ token: 'later', clientId: client.client_id, scopes: [], expiresAt: future() }, client);

        expect(await model.getAccessToken('short-lived')).toBeUndefined();
        expect(await model.getAccessToken('later')).toBeDefined();
    });
});

describe('OAuthServer default model warning', () => {
    afterEach(() => {
        vi.unstubAllEnvs();
        vi.restoreAllMocks();
    });

    const options = { authorizationUrl: new URL('http://localhost:3000/consent') };

    it('warns once when no model is given in production', () => {
        vi.stubEnv('NODE_ENV', 'production');
        const emitWarning = vi.spyOn(process, 'emitWarning').mockImplementation(() => {});

        new OAuthServer(options);
        new OAuthServer(options);

        expect(emitWarning).toHaveBeenCalledTimes(1);
        expect(emitWarning).toHaveBeenCalledWith(expect.stringContaining('process memory'), { code: 'MCP_OAUTH_MEMORY_MODEL' });
    });

    it('does not warn outside production, or when a model is given', () => {
        const emitWarning = vi.spyOn(process, 'emitWarning').mockImplementation(() => {});

        new OAuthServer(options);
        vi.stubEnv('NODE_ENV', 'production');
        new OAuthServer({ ...options, model: new MemoryOAuthServerModel() });

        expect(emitWarning).not.toHaveBeenCalled();
    });
});
