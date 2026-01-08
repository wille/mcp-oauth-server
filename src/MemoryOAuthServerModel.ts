import { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import debug from 'debug';
import { OAuthServerModel } from './OAuthServerModel';
import { AccessToken, RefreshToken, AuthorizationCode } from './types';

const log = debug('oauth:MemoryOAuthServerModel');

export class MemoryOAuthServerModel implements OAuthServerModel {
    private accessTokens = new Map<string, AccessToken>();
    private refreshTokens = new Map<string, RefreshToken>();
    private clients = new Map<string, OAuthClientInformationFull>();
    private authorizationCodes = new Map<string, AuthorizationCode>();

    async saveAuthorizationCode(params: AuthorizationCode): Promise<void> {
        await this.authorizationCodes.set(params.authorizationCode, params);
    }

    async getAuthorizationCode(authorizationCode: string): Promise<AuthorizationCode | undefined> {
        return this.authorizationCodes.get(authorizationCode);
    }

    async saveAccessToken(token: AccessToken, client: OAuthClientInformationFull): Promise<void> {
        this.accessTokens.set(token.token, token);
    }

    async revokeAuthorizationCode(authorizationCode: string): Promise<void> {
        this.authorizationCodes.delete(authorizationCode);
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

    async getRefreshToken(refreshToken: string): Promise<RefreshToken | undefined> {
        return this.refreshTokens.get(refreshToken);
    }

    async revokeRefreshToken(refreshToken: string): Promise<void> {
        this.refreshTokens.delete(refreshToken);
    }

    async getClient(clientId: string) {
        return this.clients.get(clientId);
    }

    async registerClient(clientMetadata: OAuthClientInformationFull) {
        log('registerClient', clientMetadata);

        this.clients.set(clientMetadata.client_id, clientMetadata);
        return clientMetadata;
    }
}
