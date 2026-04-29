import crypto from 'node:crypto';

/** OAuth 2.0 device authorization grant (RFC 8628) */
export const DEVICE_AUTHORIZATION_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ23456789';

/**
 * Normalize a user code for lookup (case-insensitive, ignores hyphen/spacing).
 */
export function normalizeDeviceUserCode(userCode: string): string {
    return userCode.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
}

/**
 * RFC 8628-style user code: 8 wearable characters as XXXX-XXXX.
 */
export function generateDeviceUserCode(): string {
    const bytes = crypto.randomBytes(8);
    let raw = '';
    for (let i = 0; i < 8; i++) {
        raw += USER_CODE_ALPHABET[bytes[i]! % USER_CODE_ALPHABET.length];
    }
    return `${raw.slice(0, 4)}-${raw.slice(4)}`;
}

export function generateDeviceCode(): string {
    return crypto.randomBytes(32).toString('base64url');
}
