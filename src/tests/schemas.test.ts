import { describe, it, expect } from 'vitest';
import { OAuthClientMetadataSchema } from '../schemas.js';

const baseMetadata = {
    redirect_uris: ['https://client.example.com/callback'],
};

/**
 * The URL-valued fields a client supplies at registration. Most are there to be shown on a
 * consent screen, so a script-bearing scheme in any of them is XSS on the authorization
 * server's origin, on the page where the user is granting access.
 *
 * Kept as one table deliberately: policy_uri was declared as a bare string while its siblings
 * used SafeUrlSchema, and a per-field test would have hidden that. A new field added without the
 * shared schema should show up here.
 */
const CLIENT_SUPPLIED_URL_FIELDS = ['client_uri', 'logo_uri', 'tos_uri', 'policy_uri', 'jwks_uri'] as const;

const SCRIPT_SCHEMES = ['javascript:alert(1)', 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==', 'vbscript:msgbox(1)'];

describe('OAuthClientMetadataSchema URL fields', () => {
    describe.each(CLIENT_SUPPLIED_URL_FIELDS)('%s', (field) => {
        it.each(SCRIPT_SCHEMES)('rejects %s', (url) => {
            const result = OAuthClientMetadataSchema.safeParse({ ...baseMetadata, [field]: url });

            expect(result.success).toBe(false);
        });

        it('accepts an https URL', () => {
            const result = OAuthClientMetadataSchema.safeParse({ ...baseMetadata, [field]: 'https://client.example.com/page' });

            expect(result.success).toBe(true);
        });

        it('rejects a value that is not a URL at all', () => {
            const result = OAuthClientMetadataSchema.safeParse({ ...baseMetadata, [field]: 'see our website' });

            expect(result.success).toBe(false);
        });
    });

    // logo_uri, tos_uri and policy_uri tolerate '' for compatibility with clients that send
    // empty strings for fields they have not filled in.
    describe.each(['logo_uri', 'tos_uri', 'policy_uri'] as const)('%s', (field) => {
        it('treats an empty string as absent', () => {
            const result = OAuthClientMetadataSchema.safeParse({ ...baseMetadata, [field]: '' });

            expect(result.success).toBe(true);
            expect(result.success && result.data[field]).toBeUndefined();
        });
    });

    it('rejects script schemes in redirect_uris', () => {
        for (const url of SCRIPT_SCHEMES) {
            expect(OAuthClientMetadataSchema.safeParse({ redirect_uris: [url] }).success).toBe(false);
        }
    });
});
