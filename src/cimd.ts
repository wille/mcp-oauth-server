import * as z from 'zod/v4';
import { OAuthClientMetadataSchema } from './schemas.js';
import { ClientIdMetadataDocument } from './types.js';
import { InvalidClientError } from './errors.js';
import debug from 'debug';

const log = debug('oauth:cimd');

/**
 * OAuth Client ID Metadata Documents (CIMD).
 *
 * Clients use an HTTPS URL as their `client_id`; the authorization server fetches a JSON
 * metadata document from that URL and validates it. This lets clients and servers with no
 * prior relationship interoperate without dynamic registration.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00
 * @see https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration#client-id-metadata-documents
 */
export interface ClientIdMetadataDocumentOptions {
    /**
     * Trust policy hook, called before fetching a metadata document.
     * Return `false` to reject the client_id URL (e.g. enforce a domain allowlist).
     *
     * The built-in protections only reject non-HTTPS URLs and IP-literal/localhost hosts —
     * they do not protect against DNS rebinding or requests to internal hostnames. Deploy
     * an allowlist here (or egress filtering) if the server can reach internal services.
     */
    validateClientIdUrl?: (url: URL) => boolean | Promise<boolean>;

    /**
     * How long a fetched document may be cached when the response carries no caching headers.
     * A `Cache-Control: max-age` on the response takes precedence (clamped to {@link maxCacheTtlSeconds});
     * `no-store` / `no-cache` disables caching for that document.
     *
     * Documents are cached through {@link OAuthServerModel.saveClientIdMetadataDocument}.
     * @default 300
     */
    defaultCacheTtlSeconds?: number;

    /**
     * Upper bound on how long a document may be cached, regardless of its Cache-Control header.
     * @default 3600
     */
    maxCacheTtlSeconds?: number;

    /**
     * Timeout for the metadata document fetch, in milliseconds.
     * @default 5000
     */
    fetchTimeoutMs?: number;

    /**
     * Custom fetch implementation (testing, proxying).
     * @default globalThis.fetch
     */
    fetch?: typeof fetch;
}

/** Documents larger than this are rejected. */
const MAX_DOCUMENT_SIZE_BYTES = 10 * 1024;

/**
 * A client metadata document is standard RFC 7591 client metadata plus a required
 * `client_id` (which must equal the document URL) and `client_name`.
 */
export const ClientIdMetadataDocumentSchema = OAuthClientMetadataSchema.extend({
    client_id: z.string(),
    client_name: z.string(),
});

const IPV4_HOSTNAME = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Whether a `client_id` is a Client ID Metadata Document URL: an HTTPS URL with a
 * path component (e.g. `https://example.com/client.json`) and no fragment or credentials.
 */
export function isClientIdMetadataDocumentUrl(clientId: string): boolean {
    if (!clientId.startsWith('https://') || !URL.canParse(clientId)) {
        return false;
    }
    const url = new URL(clientId);
    return url.pathname.length > 1 && !url.hash && !url.username && !url.password;
}

/**
 * Fetches and validates Client ID Metadata Documents.
 *
 * Caching is the caller's responsibility: the returned {@link ClientIdMetadataDocument.expiresAt}
 * reflects the response's Cache-Control headers (in the past when the document must not be cached).
 * `OAuthServer` persists documents through the {@link OAuthServerModel}.
 */
export class ClientIdMetadataDocumentFetcher {
    constructor(private options: ClientIdMetadataDocumentOptions = {}) {}

    async fetchClient(clientId: string): Promise<ClientIdMetadataDocument> {
        const url = new URL(clientId);

        // SSRF: never fetch loopback or IP-literal hosts. See ClientIdMetadataDocumentOptions.validateClientIdUrl
        // for the trust-policy hook covering everything these syntactic checks cannot.
        if (
            url.hostname === 'localhost' ||
            url.hostname.endsWith('.localhost') ||
            url.hostname.startsWith('[') ||
            IPV4_HOSTNAME.test(url.hostname)
        ) {
            throw new InvalidClientError('client_id metadata document host is not allowed');
        }

        if (this.options.validateClientIdUrl && !(await this.options.validateClientIdUrl(url))) {
            throw new InvalidClientError('client_id metadata document URL is not trusted by this authorization server');
        }

        const fetchImpl = this.options.fetch ?? fetch;
        let response: Response;
        try {
            response = await fetchImpl(clientId, {
                redirect: 'error',
                signal: AbortSignal.timeout(this.options.fetchTimeoutMs ?? 5000),
                headers: { accept: 'application/json' },
            });
        } catch (error) {
            log('fetch failed', clientId, error);
            throw new InvalidClientError('Failed to fetch client_id metadata document');
        }

        if (!response.ok) {
            throw new InvalidClientError(`Failed to fetch client_id metadata document: HTTP ${response.status}`);
        }

        // Cheap rejection when the server declares an oversized body. Only a hint: the header
        // is absent on chunked responses and a hostile server can understate it, so readBody
        // enforces the real limit.
        const contentLength = response.headers.get('content-length');
        if (contentLength && Number(contentLength) > MAX_DOCUMENT_SIZE_BYTES) {
            throw new InvalidClientError('client_id metadata document is too large');
        }

        const body = await this.readBody(response);

        let json: unknown;
        try {
            json = JSON.parse(body);
        } catch {
            throw new InvalidClientError('client_id metadata document is not valid JSON');
        }

        const result = ClientIdMetadataDocumentSchema.safeParse(json);
        if (!result.success) {
            throw new InvalidClientError(`Invalid client_id metadata document: ${result.error.message}`);
        }

        if (result.data.client_id !== clientId) {
            throw new InvalidClientError('client_id in metadata document does not match the document URL');
        }

        if (result.data.redirect_uris.length === 0) {
            throw new InvalidClientError('client_id metadata document must include at least one redirect_uri');
        }

        log('fetched client', clientId);

        return {
            client: result.data,
            expiresAt: new Date(Date.now() + this.cacheTtlMs(response.headers.get('cache-control'))),
        };
    }

    /**
     * Read the response body, stopping as soon as it exceeds {@link MAX_DOCUMENT_SIZE_BYTES}.
     *
     * `response.text()` would buffer the whole body before anything could check its size, so
     * a chunked response with no `content-length` could make this server hold an arbitrary
     * amount of attacker-chosen data. The fetch timeout does not help: it bounds how long the
     * transfer may run, not how much arrives in that time.
     *
     * The client_id is supplied by whoever is calling the authorization endpoint, so the URL
     * being fetched is attacker-controlled by design.
     */
    private async readBody(response: Response): Promise<string> {
        if (!response.body) {
            return await response.text();
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let received = 0;
        let body = '';

        try {
            for (;;) {
                const { done, value } = await reader.read();
                if (done) {
                    break;
                }

                received += value.byteLength;
                if (received > MAX_DOCUMENT_SIZE_BYTES) {
                    throw new InvalidClientError('client_id metadata document is too large');
                }

                // stream: true so a multi-byte character split across two chunks survives.
                body += decoder.decode(value, { stream: true });
            }
            body += decoder.decode();
        } finally {
            // Releases the connection: on the oversize path this stops the remote from
            // continuing to send, which is the whole point of bailing out early.
            await reader.cancel().catch(() => {});
        }

        return body;
    }

    private cacheTtlMs(cacheControl: string | null): number {
        const maxTtl = this.options.maxCacheTtlSeconds ?? 3600;
        if (cacheControl) {
            const directives = cacheControl.toLowerCase();
            if (/\bno-store\b/.test(directives) || /\bno-cache\b/.test(directives)) {
                return 0;
            }
            const maxAge = directives.match(/\bmax-age=(\d+)/);
            if (maxAge) {
                return Math.min(Number(maxAge[1]), maxTtl) * 1000;
            }
        }
        return Math.min(this.options.defaultCacheTtlSeconds ?? 300, maxTtl) * 1000;
    }
}
