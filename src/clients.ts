import { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';

/**
 * Stores information about registered OAuth clients for this server.
 */
export interface OAuthRegisteredClientsStore {
    /**
     * Returns information about a registered client, based on its ID.
     */
    getClient(clientId: string): OAuthClientInformationFull | undefined | Promise<OAuthClientInformationFull | undefined>;
}
