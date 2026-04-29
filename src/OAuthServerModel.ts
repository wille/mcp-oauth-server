import { OAuthClientInformationFull } from './schemas.js';
import { OAuthClientMetadata } from './schemas.js';
import { OAuthRegisteredClientsStore } from './clients.js';
import { AuthorizationCode, AccessToken, RefreshToken, DeviceAuthorization } from './types.js';

export interface OAuthServerModel extends OAuthRegisteredClientsStore {
    registerClient?(client: OAuthClientMetadata): Promise<OAuthClientInformationFull>;

    saveAuthorizationCode?(code: AuthorizationCode, client: OAuthClientInformationFull): Promise<void>;
    getAuthorizationCode?(authorizationCode: string): Promise<AuthorizationCode | undefined>;
    revokeAuthorizationCode?(authorizationCode: string): Promise<void>;

    saveDeviceAuthorization?(device: DeviceAuthorization): Promise<void>;
    getDeviceAuthorizationByDeviceCode?(deviceCode: string): Promise<DeviceAuthorization | undefined>;
    getDeviceAuthorizationByUserCode?(normalizedUserCode: string): Promise<DeviceAuthorization | undefined>;
    deleteDeviceAuthorization?(deviceCode: string): Promise<void>;

    saveAccessToken(token: AccessToken, client: OAuthClientInformationFull): Promise<void>;
    getAccessToken(accessToken: string): Promise<AccessToken | undefined>;
    revokeAccessToken(accessToken: string): Promise<void>;

    saveRefreshToken(token: RefreshToken, client: OAuthClientInformationFull): Promise<void>;
    getRefreshToken(refreshToken: string): Promise<AccessToken | undefined>;
    revokeRefreshToken(refreshToken: string): Promise<void>;

    generateToken?(): string;
}
