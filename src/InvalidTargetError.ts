import { OAuthError } from '@modelcontextprotocol/sdk/server/auth/errors.js';

/**
 * "The requested resource is invalid, missing, unknown, or malformed."
 *
 * @see https://www.rfc-editor.org/rfc/rfc8707.html#section-5.2
 */
export class InvalidTargetError extends OAuthError {
    static errorCode = 'invalid_target';

    constructor(message: string = 'The requested resource is invalid, missing, unknown, or malformed.') {
        super(message);
    }
}
