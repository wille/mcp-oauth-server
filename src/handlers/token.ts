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
import { parseScope } from '../scope.js';

export type TokenHandlerOptions = {
    provider: OAuthServer;
    /**
     * Rate limiting configuration for the token endpoint.
     * Set to false to disable rate limiting for this endpoint.
     */
    rateLimit?: Partial<RateLimitOptions> | false;
    /**
     * Rate limiting for device authorization polls (`grant_type` of
     * `urn:ietf:params:oauth:grant-type:device_code`), which are counted separately from
     * every other token request.
     *
     * A device is told to poll every {@link OAuthServer.devicePollIntervalSeconds} for as long
     * as the user takes, so one well-behaved device sends far more requests than
     * {@link rateLimit} is sized for - 180 in fifteen minutes at the default five seconds.
     * Counting those against the general limit locked devices out a few minutes into a flow.
     *
     * Defaults to twice what a single device polling at the advertised interval sends in the
     * window, per IP. Pacing of an individual device code is not this limiter's job: the grant
     * answers `slow_down` to a device that polls faster than its interval.
     *
     * Set to false to disable. Also disabled when {@link rateLimit} is false and this is unset.
     * Only applies when the provider has the device grant enabled.
     */
    devicePollRateLimit?: Partial<RateLimitOptions> | false;
};

const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;

function isDevicePoll(req: express.Request): boolean {
    return req.body?.grant_type === DEVICE_AUTHORIZATION_GRANT_TYPE;
}

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

export function tokenHandler({
    provider,
    rateLimit: rateLimitConfig,
    devicePollRateLimit: devicePollRateLimitConfig = rateLimitConfig === false ? false : undefined,
}: TokenHandlerOptions): RequestHandler {
    const deviceGrantEnabled = provider.grantTypes.includes(DEVICE_AUTHORIZATION_GRANT_TYPE);

    // Nested router so we can configure middleware and restrict HTTP method
    const router = express.Router();

    router.use(allowedMethods(['POST']));
    router.use(express.urlencoded({ extended: false }));

    // Apply rate limiting unless explicitly disabled. The body is parsed above, so the limiters
    // can tell device polls from everything else.
    if (rateLimitConfig !== false) {
        const callerSkip = rateLimitConfig?.skip;
        router.use(
            rateLimit({
                windowMs: RATE_LIMIT_WINDOW_MS,
                max: 50, // 50 requests per windowMs
                standardHeaders: true,
                legacyHeaders: false,
                message: new TooManyRequestsError('You have exceeded the rate limit for token requests').toResponseObject(),
                ...rateLimitConfig,
                // Device polls have their own limiter below.
                skip: deviceGrantEnabled ? async (req, res) => isDevicePoll(req) || ((await callerSkip?.(req, res)) ?? false) : callerSkip,
            }),
        );
    }

    if (deviceGrantEnabled && devicePollRateLimitConfig !== false) {
        const windowMs = devicePollRateLimitConfig?.windowMs ?? RATE_LIMIT_WINDOW_MS;
        const pollsPerWindow = Math.ceil(windowMs / 1000 / Math.max(provider.devicePollIntervalSeconds, 1));
        router.use(
            rateLimit({
                windowMs,
                max: pollsPerWindow * 2,
                standardHeaders: true,
                legacyHeaders: false,
                message: new TooManyRequestsError('You have exceeded the rate limit for device authorization polls').toResponseObject(),
                skip: (req) => !isDevicePoll(req),
                ...devicePollRateLimitConfig,
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

                    const scopes = parseScope(scope);
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
                    const scopes = parseScope(scope);
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
