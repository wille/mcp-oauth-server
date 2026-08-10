import { describe, it, expect } from 'vitest';
import { isSecureRedirectUri, redirectUriMatches } from '../redirect-uri.js';

describe('redirectUriMatches', () => {
    it('matches identical URIs', () => {
        expect(redirectUriMatches('https://example.com/callback', 'https://example.com/callback')).toBe(true);
    });

    it('rejects different non-loopback URIs', () => {
        expect(redirectUriMatches('https://malicious.com/callback', 'https://example.com/callback')).toBe(false);
    });

    it('rejects a different port on non-loopback hosts', () => {
        expect(redirectUriMatches('https://example.com:8443/callback', 'https://example.com/callback')).toBe(false);
    });

    it('allows any port for localhost', () => {
        expect(redirectUriMatches('http://localhost:51234/callback', 'http://localhost/callback')).toBe(true);
        expect(redirectUriMatches('http://localhost:51234/callback', 'http://localhost:3000/callback')).toBe(true);
    });

    it('allows any port for 127.0.0.1', () => {
        expect(redirectUriMatches('http://127.0.0.1:51234/callback', 'http://127.0.0.1/callback')).toBe(true);
    });

    it('allows any port for [::1]', () => {
        expect(redirectUriMatches('http://[::1]:51234/callback', 'http://[::1]/callback')).toBe(true);
    });

    it('does not cross-match localhost and 127.0.0.1', () => {
        expect(redirectUriMatches('http://127.0.0.1:51234/callback', 'http://localhost:3000/callback')).toBe(false);
        expect(redirectUriMatches('http://localhost:51234/callback', 'http://127.0.0.1:3000/callback')).toBe(false);
    });

    it('requires matching scheme on loopback', () => {
        expect(redirectUriMatches('https://localhost:51234/callback', 'http://localhost:3000/callback')).toBe(false);
    });

    it('requires matching path on loopback', () => {
        expect(redirectUriMatches('http://localhost:51234/other', 'http://localhost:3000/callback')).toBe(false);
    });

    it('requires matching query on loopback', () => {
        expect(redirectUriMatches('http://localhost:51234/callback?foo=bar', 'http://localhost:3000/callback')).toBe(false);
        expect(redirectUriMatches('http://localhost:51234/callback?foo=bar', 'http://localhost:3000/callback?foo=bar')).toBe(true);
    });

    it('rejects unparseable URIs', () => {
        expect(redirectUriMatches('not-a-url', 'http://localhost:3000/callback')).toBe(false);
        expect(redirectUriMatches('http://localhost:3000/callback', 'not-a-url')).toBe(false);
    });
});

/**
 * OAuth 2.1 §2.3.1 requires TLS for redirect URIs, with the RFC 8252 exceptions for URIs
 * that never cross a network.
 */
describe('isSecureRedirectUri', () => {
    it('accepts https', () => {
        expect(isSecureRedirectUri('https://app.example.com/callback')).toBe(true);
        expect(isSecureRedirectUri('https://app.example.com:8443/callback?x=1')).toBe(true);
    });

    it('rejects cleartext http on a routable host', () => {
        expect(isSecureRedirectUri('http://app.example.com/callback')).toBe(false);
        expect(isSecureRedirectUri('http://203.0.113.10/callback')).toBe(false);
        expect(isSecureRedirectUri('http://localhost.evil.example.com/callback')).toBe(false);
    });

    it('accepts http on the loopback interface (RFC 8252 §7.3)', () => {
        expect(isSecureRedirectUri('http://127.0.0.1:49152/callback')).toBe(true);
        expect(isSecureRedirectUri('http://[::1]:49152/callback')).toBe(true);
        expect(isSecureRedirectUri('http://localhost:3000/callback')).toBe(true);
    });

    it('accepts private-use URI schemes (RFC 8252 §7.1)', () => {
        expect(isSecureRedirectUri('com.example.app:/oauth2redirect')).toBe(true);
        expect(isSecureRedirectUri('com.example.app:/oauth2redirect/callback')).toBe(true);
        // Schemes real MCP clients use, which are not reverse-domain form.
        expect(isSecureRedirectUri('vscode://example.extension/callback')).toBe(true);
        expect(isSecureRedirectUri('cursor://anysphere.mcp/callback')).toBe(true);
    });

    it('rejects unparseable URIs', () => {
        expect(isSecureRedirectUri('not-a-url')).toBe(false);
        expect(isSecureRedirectUri('')).toBe(false);
    });
});
