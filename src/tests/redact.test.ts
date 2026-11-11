import { describe, it, expect, vi } from 'vitest';
import { OAuthServer } from '../OAuthServer.js';
import { MemoryOAuthServerModel } from '../MemoryOAuthServerModel.js';
import { DEVICE_AUTHORIZATION_GRANT_TYPE } from '../deviceFlow.js';
import { fingerprint, redactClient, redactErrorContext, REDACTED } from '../redact.js';
import { createTestClient } from './test-helpers.js';

describe('fingerprint', () => {
    it('is stable for one value and different for another', () => {
        expect(fingerprint('token-a')).toBe(fingerprint('token-a'));
        expect(fingerprint('token-a')).not.toBe(fingerprint('token-b'));
    });

    it('does not contain the value', () => {
        expect(fingerprint('token-a')).toMatch(/^sha256:[0-9a-f]{12}$/);
    });
});

describe('redactClient', () => {
    it("replaces the secret and leaves the caller's object alone", () => {
        const client = createTestClient({ client_secret: 'hunter2' });

        expect(redactClient(client)).toEqual({ ...client, client_secret: REDACTED });
        expect(client.client_secret).toBe('hunter2');
    });

    it('returns a public client unchanged', () => {
        const client = createTestClient();
        expect(redactClient(client)).toBe(client);
    });
});

describe('redactErrorContext', () => {
    it('passes through undefined and non-sensitive fields', () => {
        expect(redactErrorContext(undefined)).toBeUndefined();
        expect(redactErrorContext({ clientId: 'abc', scopes: ['a'] })).toEqual({ clientId: 'abc', scopes: ['a'] });
    });

    it('redacts every credential it knows about', () => {
        const context = redactErrorContext({
            client: createTestClient({ client_secret: 'hunter2' }),
            authorizationCode: 'the-code',
            codeVerifier: 'the-verifier',
            refreshToken: 'the-refresh-token',
            deviceCode: 'the-device-code',
            userCode: 'BCDF-GHJK',
            request: { token: 'the-revoked-token', token_type_hint: 'refresh_token' },
        });

        const serialized = JSON.stringify(context);
        for (const secret of [
            'hunter2',
            'the-code',
            'the-verifier',
            'the-refresh-token',
            'the-device-code',
            'BCDF-GHJK',
            'the-revoked-token',
        ]) {
            expect(serialized).not.toContain(secret);
        }
        expect(context).toMatchObject({
            refreshToken: fingerprint('the-refresh-token'),
            userCode: REDACTED,
            request: { token: fingerprint('the-revoked-token'), token_type_hint: 'refresh_token' },
        });
    });
});

describe('OAuthServer errorHandler receives no credentials', () => {
    const secrets = ['hunter2', 'the-code', 'the-verifier', 'the-refresh-token', 'the-device-code', 'the-revoked-token'];

    it('across the token, revocation and device flows', async () => {
        const errorHandler = vi.fn();
        const model = new MemoryOAuthServerModel();
        const oauthServer = new OAuthServer({
            model,
            errorHandler,
            authorizationUrl: new URL('http://localhost:3000/consent'),
            deviceAuthorizationUrl: new URL('http://localhost:3000/device'),
            grantTypes: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
            strictResource: false,
        });
        const client = createTestClient({
            client_secret: 'hunter2',
            grant_types: ['authorization_code', 'refresh_token', DEVICE_AUTHORIZATION_GRANT_TYPE],
        });

        model.revokeAccessToken = async () => {
            throw new Error('database unavailable');
        };

        await expect(oauthServer.exchangeAuthorizationCode(client, 'the-code', 'the-verifier')).rejects.toThrow();
        await expect(oauthServer.exchangeRefreshToken(client, 'the-refresh-token')).rejects.toThrow();
        await expect(oauthServer.exchangeDeviceCode(client, 'the-device-code')).rejects.toThrow();
        await expect(oauthServer.revokeToken(client, { token: 'the-revoked-token' })).rejects.toThrow();
        await expect(oauthServer.approveDeviceAuthorization('BCDF-GHJK', 'user-1')).rejects.toThrow();

        expect(errorHandler).toHaveBeenCalledTimes(5);
        const reported = JSON.stringify(errorHandler.mock.calls.map(([step, , params]) => ({ step, params })));
        for (const secret of [...secrets, 'BCDF-GHJK']) {
            expect(reported).not.toContain(secret);
        }

        // Still enough to tell which client and which credential an error was about.
        const [, , refreshParams] = errorHandler.mock.calls[1];
        expect(refreshParams.client.client_id).toBe(client.client_id);
        expect(refreshParams.refreshToken).toBe(fingerprint('the-refresh-token'));
    });
});
