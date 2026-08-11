import { describe, it, expect } from 'vitest';
import {
    OAuthClientMetadataSchema,
    OAuthMetadataSchema,
    OAuthProtectedResourceMetadataSchema,
    OpenIdProviderMetadataSchema,
} from '../schemas.js';

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

/**
 * The metadata schemas are exported, so they are used to parse documents fetched from elsewhere -
 * an authorization server's RFC 8414 document, or a resource server's RFC 9728 one - as well as to
 * type what this server publishes. Anything a remote document can put in front of a user has to go
 * through SafeUrlSchema; `z.string().url()` does not, since it accepts javascript: happily.
 */
describe('metadata schema URL fields', () => {
    const validProtectedResource = { resource: 'https://mcp.example.com/mcp' };
    const validAuthorizationServer = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/authorize',
        token_endpoint: 'https://auth.example.com/token',
        response_types_supported: ['code'],
    };
    const validOpenIdProvider = {
        ...validAuthorizationServer,
        jwks_uri: 'https://auth.example.com/jwks',
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
    };

    const cases = [
        ['OAuthProtectedResourceMetadata', OAuthProtectedResourceMetadataSchema, validProtectedResource, 'resource'],
        ['OAuthProtectedResourceMetadata', OAuthProtectedResourceMetadataSchema, validProtectedResource, 'jwks_uri'],
        ['OAuthProtectedResourceMetadata', OAuthProtectedResourceMetadataSchema, validProtectedResource, 'resource_documentation'],
        ['OAuthProtectedResourceMetadata', OAuthProtectedResourceMetadataSchema, validProtectedResource, 'resource_policy_uri'],
        ['OAuthProtectedResourceMetadata', OAuthProtectedResourceMetadataSchema, validProtectedResource, 'resource_tos_uri'],
        ['OAuthMetadata', OAuthMetadataSchema, validAuthorizationServer, 'introspection_endpoint'],
        ['OpenIdProviderMetadata', OpenIdProviderMetadataSchema, validOpenIdProvider, 'service_documentation'],
    ] as const;

    it.each(cases)('%s rejects a script scheme in %#: $3', (_name, schema, valid, field) => {
        for (const url of SCRIPT_SCHEMES) {
            expect(schema.safeParse({ ...valid, [field]: url }).success).toBe(false);
        }
    });

    it('still accepts otherwise valid documents', () => {
        expect(OAuthProtectedResourceMetadataSchema.safeParse(validProtectedResource).success).toBe(true);
        expect(OAuthMetadataSchema.safeParse(validAuthorizationServer).success).toBe(true);
        expect(OpenIdProviderMetadataSchema.safeParse(validOpenIdProvider).success).toBe(true);
        expect(
            OAuthProtectedResourceMetadataSchema.safeParse({
                ...validProtectedResource,
                resource_documentation: 'https://docs.example.com',
                resource_policy_uri: 'https://example.com/privacy',
                resource_tos_uri: 'https://example.com/tos',
            }).success,
        ).toBe(true);
    });
});
