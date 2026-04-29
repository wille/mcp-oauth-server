import { z } from 'zod/v4';

export interface AuthorizationParams {
    state?: string;
    scopes?: string[];
    codeChallenge: string;
    redirectUri: string;
    resource?: URL;
}

export interface AuthorizationCode extends Omit<AuthorizationParams, 'resource'> {
    authorizationCode: string;
    clientId: string;
    userId: string;
    expiresAt: Date;
    resource?: string;
}

export interface AccessToken {
    token: string;
    expiresAt: Date;
    scopes: string[];
    clientId: string;
    userId?: string;
    resource?: string;
}

export interface RefreshToken {
    token: string;
    expiresAt: Date;
    scopes: string[];
    clientId: string;
    userId?: string;
    resource?: string;
}

export type DeviceAuthorizationStatus = 'pending' | 'approved' | 'denied';

/**
 * Stored state for RFC 8628 device authorization.
 */
export interface DeviceAuthorization {
    deviceCode: string;
    /** Display form, e.g. XXXX-XXXX */
    userCode: string;
    clientId: string;
    scopes: string[];
    resource?: string;
    expiresAt: Date;
    /** Minimum seconds between token endpoint polls while pending */
    pollIntervalSeconds: number;
    status: DeviceAuthorizationStatus;
    userId?: string;
    /** Last time the client received authorization_pending or slow_down */
    lastPollResponseAtMs?: number;
}

/**
 * JSON body returned from the device authorization endpoint (RFC 8628 Section 3.2).
 */
export type DeviceAuthorizationEndpointResponse = {
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete?: string;
    expires_in: number;
    interval: number;
};

/**
 * Information about a validated access token, provided to request handlers.
 */
export interface AuthInfo {
    /**
     * The access token.
     */
    token: string;

    /**
     * The client ID associated with this token.
     */
    clientId: string;

    /**
     * Scopes associated with this token.
     */
    scopes: string[];

    /**
     * When the token expires (in seconds since epoch).
     */
    expiresAt?: number;

    /**
     * The RFC 8707 resource server identifier for which this token is valid.
     * If set, this MUST match the MCP server's resource identifier (minus hash fragment).
     */
    resource?: URL;

    /**
     * The user ID associated with this token, if any.
     */
    userId?: string;

    /**
     * Additional data associated with the token.
     * This field should be used for any additional data that needs to be attached to the auth info.
     */
    extra?: Record<string, unknown>;
}
