import { OAuthClientInformationFull } from './schemas.js';
import { OAuthClientMetadata } from './schemas.js';
import { OAuthRegisteredClientsStore } from './clients.js';
import { AuthorizationCode, AccessToken, RefreshToken, DeviceAuthorization, ClientIdMetadataDocument } from './types.js';

export interface OAuthServerModel extends OAuthRegisteredClientsStore {
    registerClient?(client: OAuthClientMetadata): Promise<OAuthClientInformationFull>;

    saveAuthorizationCode?(code: AuthorizationCode, client: OAuthClientInformationFull): Promise<void>;

    /**
     * Fetch an authorization code and invalidate it in the same atomic operation, but only
     * if it belongs to `clientId`. Returns `undefined` when there is no such code, when it
     * was already used, or when it belongs to another client.
     *
     * Required when the `authorization_code` grant is enabled.
     *
     * Two properties matter, and one statement gives you both:
     *
     * ```sql
     * DELETE FROM authorization_codes WHERE code = $1 AND client_id = $2 RETURNING *
     * ```
     *
     * 1. Atomic. When several requests present the same code concurrently, exactly one may
     *    receive the record. A read followed by a separate delete does not satisfy this -
     *    two requests can both observe a valid code and each be issued their own tokens,
     *    breaking the single-use requirement of OAuth 2.1 section 4.1.3.
     * 2. Scoped to the client. Matching on `client_id` inside the same statement means a
     *    request from the wrong client consumes nothing, so it cannot invalidate a code
     *    that another client is about to redeem.
     *
     * Use `UPDATE ... SET consumed_at = now() WHERE code = $1 AND client_id = $2 AND
     * consumed_at IS NULL RETURNING *` instead if you keep spent codes for auditing.
     */
    consumeAuthorizationCode?(authorizationCode: string, clientId: string): Promise<AuthorizationCode | undefined>;

    revokeAuthorizationCode?(authorizationCode: string): Promise<void>;

    saveClientIdMetadataDocument?(document: ClientIdMetadataDocument): Promise<void>;
    getClientIdMetadataDocument?(clientId: string): Promise<ClientIdMetadataDocument | undefined>;

    saveDeviceAuthorization?(device: DeviceAuthorization): Promise<void>;
    getDeviceAuthorizationByDeviceCode?(deviceCode: string): Promise<DeviceAuthorization | undefined>;
    getDeviceAuthorizationByUserCode?(normalizedUserCode: string): Promise<DeviceAuthorization | undefined>;
    deleteDeviceAuthorization?(deviceCode: string): Promise<void>;

    /**
     * Fetch an **approved** device authorization and delete it in the same atomic operation,
     * but only if it belongs to `clientId`. Returns `undefined` in every other case.
     *
     * Required when the device authorization grant is enabled.
     *
     * ```sql
     * DELETE FROM device_authorizations
     *  WHERE device_code = $1 AND client_id = $2 AND status = 'approved'
     *  RETURNING *
     * ```
     *
     * The `status = 'approved'` condition is not optional: devices poll the token endpoint
     * repeatedly while the user has not answered yet, and deleting a pending authorization
     * would abandon a flow that is still in progress. Atomicity is what stops two polls
     * arriving together from each being issued their own tokens.
     */
    consumeApprovedDeviceAuthorization?(deviceCode: string, clientId: string): Promise<DeviceAuthorization | undefined>;

    /**
     * Move a **pending** device authorization to `approved` or `denied` and return the
     * updated record, atomically. Returns `undefined` if it was not pending, which includes
     * the case where a concurrent call already resolved it.
     *
     * Required when the device authorization grant is enabled.
     *
     * ```sql
     * UPDATE device_authorizations SET status = $2, user_id = $3
     *  WHERE user_code = $1 AND status = 'pending'
     *  RETURNING *
     * ```
     *
     * Reading the row, changing it, and writing it back would let a simultaneous approve and
     * deny both believe they won, leaving the outcome down to whichever write landed last.
     */
    resolvePendingDeviceAuthorization?(
        normalizedUserCode: string,
        status: 'approved' | 'denied',
        userId?: string,
    ): Promise<DeviceAuthorization | undefined>;

    saveAccessToken(token: AccessToken, client: OAuthClientInformationFull): Promise<void>;
    getAccessToken(accessToken: string): Promise<AccessToken | undefined>;
    revokeAccessToken(accessToken: string): Promise<void>;

    saveRefreshToken(token: RefreshToken, client: OAuthClientInformationFull): Promise<void>;
    revokeRefreshToken(refreshToken: string): Promise<void>;

    /**
     * Fetch a refresh token and invalidate it in the same atomic operation, but only if it
     * belongs to `clientId`.
     *
     * Required when the `refresh_token` grant is enabled. Refresh tokens are rotated on
     * every use, so both rules from {@link consumeAuthorizationCode} apply here unchanged.
     */
    consumeRefreshToken?(refreshToken: string, clientId: string): Promise<RefreshToken | undefined>;

    generateToken?(): string;
}
