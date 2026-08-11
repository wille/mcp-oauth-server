import * as z from 'zod/v4';
import express, { RequestHandler } from 'express';
import { OAuthGrantType, OAuthServer } from '../OAuthServer.js';
import { authenticateClient } from '../middleware/clientAuth.js';
import { rateLimit, Options as RateLimitOptions } from 'express-rate-limit';
import { allowedMethods } from '../middleware/allowedMethods.js';
import {
    InvalidRequestError,
    UnsupportedGrantTypeError,
    UnauthorizedClientError,
    ServerError,
    TooManyRequestsError,
    OAuthError,
} from '../errors.js';
import { DEVICE_AUTHORIZATION_GRANT_TYPE } from '../deviceFlow.js';

export type TokenHandlerOptions = {
    provider: OAuthServer;
    /**
     * Rate limiting configuration for the token endpoint.
     * Set to false to disable rate limiting for this endpoint.
     */
    rateLimit?: Partial<RateLimitOptions> | false;
};

const TokenRequestSchema = z.object({
    grant_type: z.string(),
});

const AuthorizationCodeGrantSchema = z.object({
    code: z.string(),
    code_verifier: z.string(),
    redirect_uri: z.string().optional(),
    resource: z.string().url().optional(),
});

const RefreshTokenGrantSchema = z.object({
    refresh_token: z.string(),
    scope: z.string().optional(),
    resource: z.string().url().optional(),
});

const DeviceCodeGrantSchema = z.object({
    device_code: z.string(),
});

const ClientCredentialsGrantSchema = z.object({
    scope: z.string().optional(),
    resource: z.string().url().optional(),
});

function assertClientSupportsGrant(client: { grant_types?: string[] }, grantType: string): void {
    if (!client.grant_types?.includes(grantType)) {
        throw new UnauthorizedClientError(`Client is not authorized to use ${grantType} grant`);
    }
}

export function tokenHandler({ provider, rateLimit: rateLimitConfig }: TokenHandlerOptions): RequestHandler {
    // Nested router so we can configure middleware and restrict HTTP method
    const router = express.Router();

    router.use(allowedMethods(['POST']));
    router.use(express.urlencoded({ extended: false }));

    // Apply rate limiting unless explicitly disabled
    if (rateLimitConfig !== false) {
        router.use(
            rateLimit({
                windowMs: 15 * 60 * 1000, // 15 minutes
                max: 50, // 50 requests per windowMs
                standardHeaders: true,
                legacyHeaders: false,
                message: new TooManyRequestsError('You have exceeded the rate limit for token requests').toResponseObject(),
                ...rateLimitConfig,
            }),
        );
    }

    // Authenticate and extract client details
    router.use(authenticateClient({ clientsStore: provider }));

    router.post('/', async (req, res) => {
        res.setHeader('Cache-Control', 'no-store');

        try {
            const parseResult = TokenRequestSchema.safeParse(req.body);
            if (!parseResult.success) {
                throw new InvalidRequestError(parseResult.error.message);
            }

            const { grant_type } = parseResult.data;

            const client = req.client;
            if (!client) {
                // This should never happen
                throw new ServerError('Internal Server Error');
            }

            // What the server supports is checked before what the client is registered for, so
            // that a grant this server does not offer is always reported as
            // unsupported_grant_type. Checking the client first would answer
            // unauthorized_client to a client that had not registered for the grant, which
            // reads as "ask for this grant and try again" - and registration would accept the
            // request, since registerClient only refuses a client when none of its grants are
            // supported. The client would come back to a different error for an unchanged
            // server configuration.
            if (!provider.grantTypes.includes(grant_type as OAuthGrantType)) {
                throw new UnsupportedGrantTypeError('The grant type is not supported by this authorization server.');
            }

            switch (grant_type) {
                case 'authorization_code': {
                    assertClientSupportsGrant(client, 'authorization_code');
                    const parseResult = AuthorizationCodeGrantSchema.safeParse(req.body);
                    if (!parseResult.success) {
                        throw new InvalidRequestError(parseResult.error.message);
                    }

                    const { code, code_verifier, redirect_uri, resource } = parseResult.data;

                    const tokens = await provider.exchangeAuthorizationCode(
                        client,
                        code,
                        code_verifier,
                        redirect_uri,
                        resource ? new URL(resource) : undefined,
                    );
                    res.status(200).json(tokens);
                    break;
                }

                case 'refresh_token': {
                    assertClientSupportsGrant(client, 'refresh_token');
                    const parseResult = RefreshTokenGrantSchema.safeParse(req.body);
                    if (!parseResult.success) {
                        throw new InvalidRequestError(parseResult.error.message);
                    }

                    const { refresh_token, scope, resource } = parseResult.data;

                    const scopes = scope?.split(' ');
                    const tokens = await provider.exchangeRefreshToken(
                        client,
                        refresh_token,
                        scopes,
                        resource ? new URL(resource) : undefined,
                    );
                    res.status(200).json(tokens);
                    break;
                }

                case DEVICE_AUTHORIZATION_GRANT_TYPE: {
                    assertClientSupportsGrant(client, DEVICE_AUTHORIZATION_GRANT_TYPE);
                    const parseResult = DeviceCodeGrantSchema.safeParse(req.body);
                    if (!parseResult.success) {
                        throw new InvalidRequestError(parseResult.error.message);
                    }
                    const { device_code } = parseResult.data;
                    const tokens = await provider.exchangeDeviceCode(client, device_code);
                    res.status(200).json(tokens);
                    break;
                }

                case 'client_credentials': {
                    assertClientSupportsGrant(client, 'client_credentials');

                    const parseResult = ClientCredentialsGrantSchema.safeParse(req.body);
                    if (!parseResult.success) {
                        throw new InvalidRequestError(parseResult.error.message);
                    }

                    const { scope, resource } = parseResult.data;
                    const scopes = scope?.split(' ');
                    const tokens = await provider.exchangeClientCredentials(client, scopes, resource ? new URL(resource) : undefined);
                    res.status(200).json(tokens);
                    break;
                }

                default:
                    // Unreachable for a client: the guard above rejects anything absent from
                    // provider.grantTypes. Left as a backstop for a supported grant type that
                    // has no branch here.
                    throw new UnsupportedGrantTypeError('The grant type is not supported by this authorization server.');
            }
        } catch (error) {
            if (error instanceof OAuthError) {
                const status = error instanceof ServerError ? 500 : 400;
                res.status(status).json(error.toResponseObject());
            } else {
                const serverError = new ServerError('Internal Server Error');
                res.status(500).json(serverError.toResponseObject());
            }
        }
    });

    return router;
}
