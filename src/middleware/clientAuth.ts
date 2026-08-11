import * as z from 'zod/v4';
import { RequestHandler } from 'express';
import crypto from 'node:crypto';
import { OAuthRegisteredClientsStore } from '../clients.js';
import { OAuthClientInformationFull } from '../schemas.js';
import { InvalidRequestError, InvalidClientError, ServerError, OAuthError } from '../errors.js';

export type ClientAuthenticationMiddlewareOptions = {
    /**
     * A store used to read information about registered OAuth clients.
     */
    clientsStore: OAuthRegisteredClientsStore;
};

const ClientAuthenticatedRequestSchema = z.object({
    client_id: z.string(),
    client_secret: z.string().optional(),
});

declare module 'express-serve-static-core' {
    interface Request {
        /**
         * The authenticated client for this request, if the `authenticateClient` middleware was used.
         */
        client?: OAuthClientInformationFull;
    }
}

/**
 * Compares two secrets in constant time, so the response time cannot be used to work out how
 * much of a guess was right.
 *
 * Hashing first keeps that true when the lengths differ, which `crypto.timingSafeEqual`
 * rejects outright, and avoids leaking the length of the real secret.
 */
function secretMatches(provided: string, expected: string): boolean {
    const providedDigest = crypto.createHash('sha256').update(provided).digest();
    const expectedDigest = crypto.createHash('sha256').update(expected).digest();
    return crypto.timingSafeEqual(providedDigest, expectedDigest);
}

export function authenticateClient({ clientsStore }: ClientAuthenticationMiddlewareOptions): RequestHandler {
    return async (req, res, next) => {
        try {
            // Credentials come from the request body only - `client_secret_post`, which OAuth
            // 2.1 §2.4.1 requires and this server advertises. `client_secret_basic` is optional
            // there and deliberately not implemented.
            const result = ClientAuthenticatedRequestSchema.safeParse(req.body);
            if (!result.success) {
                throw new InvalidRequestError(String(result.error));
            }
            const { client_id, client_secret } = result.data;

            const client = await clientsStore.getClient(client_id);
            if (!client) {
                throw new InvalidClientError('Invalid client_id');
            }
            if (client.client_secret) {
                if (!client_secret) {
                    throw new InvalidClientError('Client secret is required');
                }
                if (!secretMatches(client_secret, client.client_secret)) {
                    throw new InvalidClientError('Invalid client_secret');
                }
                if (client.client_secret_expires_at && client.client_secret_expires_at < Math.floor(Date.now() / 1000)) {
                    throw new InvalidClientError('Client secret has expired');
                }
            }

            req.client = client;
            next();
        } catch (error) {
            if (error instanceof OAuthError) {
                const status = error instanceof ServerError ? 500 : 400;
                res.status(status).json(error.toResponseObject());
            } else {
                const serverError = new ServerError('Internal Server Error');
                res.status(500).json(serverError.toResponseObject());
            }
        }
    };
}
