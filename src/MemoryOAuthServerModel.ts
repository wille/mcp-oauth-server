import { OAuthClientInformationFull } from './schemas.js';
import debug from 'debug';
import { OAuthServerModel } from './OAuthServerModel';
import { AccessToken, RefreshToken, AuthorizationCode, DeviceAuthorization, ClientIdMetadataDocument } from './types';
import { normalizeDeviceUserCode } from './deviceFlow';

const log = debug('oauth:MemoryOAuthServerModel');

const MAX_CLIENT_ID_METADATA_DOCUMENTS = 1000;

export class MemoryOAuthServerModel implements OAuthServerModel {
    private accessTokens = new Map<string, AccessToken>();
    private refreshTokens = new Map<string, RefreshToken>();
    private clients = new Map<string, OAuthClientInformationFull>();
    private authorizationCodes = new Map<string, AuthorizationCode>();
    private deviceByDeviceCode = new Map<string, DeviceAuthorization>();
    private deviceCodeByUserCode = new Map<string, string>();
    private clientIdMetadataDocuments = new Map<string, ClientIdMetadataDocument>();

    async saveAuthorizationCode(params: AuthorizationCode, _client?: OAuthClientInformationFull): Promise<void> {
        this.authorizationCodes.set(params.authorizationCode, params);
    }

    /**
     * Read a code without consuming it.
     *
     * Not part of {@link OAuthServerModel} and never called by the library - the flows only
     * ever consume. Kept here for tests and local introspection.
     */
    async getAuthorizationCode(authorizationCode: string): Promise<AuthorizationCode | undefined> {
        return this.authorizationCodes.get(authorizationCode);
    }

    async saveAccessToken(token: AccessToken, client: OAuthClientInformationFull): Promise<void> {
        this.accessTokens.set(token.token, token);
    }

    async revokeAuthorizationCode(authorizationCode: string): Promise<void> {
        this.authorizationCodes.delete(authorizationCode);
    }

    /**
     * Atomic because the lookup and the delete share one synchronous block: there is no
     * await between them, so no other task can observe the code in between. A store that
     * talks to a database must get this from the database instead - see
     * {@link OAuthServerModel.consumeAuthorizationCode}.
     */
    async consumeAuthorizationCode(authorizationCode: string, clientId: string): Promise<AuthorizationCode | undefined> {
        const code = this.authorizationCodes.get(authorizationCode);
        if (!code || code.clientId !== clientId) {
            return undefined;
        }
        this.authorizationCodes.delete(authorizationCode);
        return code;
    }

    async getAccessToken(accessToken: string): Promise<AccessToken | undefined> {
        return this.accessTokens.get(accessToken);
    }

    async revokeAccessToken(accessToken: string): Promise<void> {
        this.accessTokens.delete(accessToken);
    }

    async saveRefreshToken(token: RefreshToken, client: OAuthClientInformationFull): Promise<void> {
        this.refreshTokens.set(token.token, token);
    }

    /** Read a refresh token without consuming it. Introspection only, like {@link getAuthorizationCode}. */
    async getRefreshToken(refreshToken: string): Promise<RefreshToken | undefined> {
        return this.refreshTokens.get(refreshToken);
    }

    async revokeRefreshToken(refreshToken: string): Promise<void> {
        this.refreshTokens.delete(refreshToken);
    }

    /** Atomic for the same reason as {@link consumeAuthorizationCode}. */
    async consumeRefreshToken(refreshToken: string, clientId: string): Promise<RefreshToken | undefined> {
        const token = this.refreshTokens.get(refreshToken);
        if (!token || token.clientId !== clientId) {
            return undefined;
        }
        this.refreshTokens.delete(refreshToken);
        return token;
    }

    async getClient(clientId: string) {
        return this.clients.get(clientId);
    }

    async registerClient(clientMetadata: OAuthClientInformationFull) {
        log('registerClient', clientMetadata);

        this.clients.set(clientMetadata.client_id, clientMetadata);
        return clientMetadata;
    }

    async saveClientIdMetadataDocument(document: ClientIdMetadataDocument): Promise<void> {
        if (this.clientIdMetadataDocuments.size >= MAX_CLIENT_ID_METADATA_DOCUMENTS) {
            this.clientIdMetadataDocuments.delete(this.clientIdMetadataDocuments.keys().next().value!);
        }
        this.clientIdMetadataDocuments.set(document.client.client_id, document);
    }

    async getClientIdMetadataDocument(clientId: string): Promise<ClientIdMetadataDocument | undefined> {
        return this.clientIdMetadataDocuments.get(clientId);
    }

    async saveDeviceAuthorization(device: DeviceAuthorization): Promise<void> {
        const key = normalizeDeviceUserCode(device.userCode);
        this.deviceByDeviceCode.set(device.deviceCode, device);
        this.deviceCodeByUserCode.set(key, device.deviceCode);
    }

    async getDeviceAuthorizationByDeviceCode(deviceCode: string): Promise<DeviceAuthorization | undefined> {
        return this.deviceByDeviceCode.get(deviceCode);
    }

    async getDeviceAuthorizationByUserCode(normalizedUserCode: string): Promise<DeviceAuthorization | undefined> {
        const deviceCode = this.deviceCodeByUserCode.get(normalizedUserCode);
        if (!deviceCode) {
            return undefined;
        }
        return this.deviceByDeviceCode.get(deviceCode);
    }

    async deleteDeviceAuthorization(deviceCode: string): Promise<void> {
        const device = this.deviceByDeviceCode.get(deviceCode);
        if (device) {
            this.deviceCodeByUserCode.delete(normalizeDeviceUserCode(device.userCode));
        }
        this.deviceByDeviceCode.delete(deviceCode);
    }

    /** Atomic for the same reason as {@link consumeAuthorizationCode}. */
    async consumeApprovedDeviceAuthorization(deviceCode: string, clientId: string): Promise<DeviceAuthorization | undefined> {
        const device = this.deviceByDeviceCode.get(deviceCode);
        if (!device || device.clientId !== clientId || device.status !== 'approved') {
            return undefined;
        }
        this.deviceByDeviceCode.delete(deviceCode);
        this.deviceCodeByUserCode.delete(normalizeDeviceUserCode(device.userCode));
        return device;
    }

    /** Atomic for the same reason as {@link consumeAuthorizationCode}. */
    async resolvePendingDeviceAuthorization(
        normalizedUserCode: string,
        status: 'approved' | 'denied',
        userId?: string,
    ): Promise<DeviceAuthorization | undefined> {
        const deviceCode = this.deviceCodeByUserCode.get(normalizedUserCode);
        const device = deviceCode ? this.deviceByDeviceCode.get(deviceCode) : undefined;
        if (!device || device.status !== 'pending') {
            return undefined;
        }
        device.status = status;
        if (userId !== undefined) {
            device.userId = userId;
        }
        return device;
    }
}
