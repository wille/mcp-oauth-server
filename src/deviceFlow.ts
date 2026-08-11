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
 *
 * `crypto.randomInt` rather than `randomBytes` with `%`: the alphabet's length does not divide
 * 256, so reducing a byte would over-represent the first `256 % length` characters - with the
 * current 28 characters, B, C, D and F would each come up 11% more often than the rest.
 * `randomInt` rejection-samples internally, so the codes stay uniform if the alphabet or the
 * length is ever changed.
 */
export function generateDeviceUserCode(): string {
    let raw = '';
    for (let i = 0; i < 8; i++) {
        raw += USER_CODE_ALPHABET[crypto.randomInt(USER_CODE_ALPHABET.length)];
    }
    return `${raw.slice(0, 4)}-${raw.slice(4)}`;
}

export function generateDeviceCode(): string {
    return crypto.randomBytes(32).toString('base64url');
}
