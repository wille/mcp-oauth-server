import { describe, it, expect } from 'vitest';
import { redirectUriMatches } from '../redirect-uri.js';

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
