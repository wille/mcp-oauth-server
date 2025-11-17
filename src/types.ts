import { AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider';

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
    userId: string;
    resource?: string;
}

export interface RefreshToken {
    token: string;
    expiresAt: Date;
    scopes: string[];
    clientId: string;
    userId: string;
    resource?: string;
}
