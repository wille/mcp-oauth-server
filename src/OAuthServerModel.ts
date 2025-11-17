import { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients';
import { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth';
import { AuthorizationCode, AccessToken, RefreshToken } from './types';

export interface OAuthServerModel extends OAuthRegisteredClientsStore {
    saveAuthorizationCode(code: AuthorizationCode, client: OAuthClientInformationFull): Promise<void>;
    getAuthorizationCode(authorizationCode: string): Promise<AuthorizationCode | undefined>;
    revokeAuthorizationCode(authorizationCode: string): Promise<void>;

    saveAccessToken(token: AccessToken, client: OAuthClientInformationFull): Promise<void>;
    getAccessToken(accessToken: string): Promise<AccessToken | undefined>;
    revokeAccessToken(accessToken: string): Promise<void>;

    saveRefreshToken(token: RefreshToken, client: OAuthClientInformationFull): Promise<void>;
    getRefreshToken(refreshToken: string): Promise<AccessToken | undefined>;
    revokeRefreshToken(refreshToken: string): Promise<void>;

    generateToken?(): string;
}
