import * as z from 'zod/v4';
import express, { RequestHandler } from 'express';
import { OAuthServer } from '../OAuthServer.js';
import { authenticateClient } from '../middleware/clientAuth.js';
import { rateLimit, Options as RateLimitOptions } from 'express-rate-limit';
import { allowedMethods } from '../middleware/allowedMethods.js';
import { InvalidRequestError, ServerError, TooManyRequestsError, OAuthError, UnsupportedGrantTypeError } from '../errors.js';

export type DeviceAuthorizationHandlerOptions = {
    provider: OAuthServer;
    /**
     * Rate limiting for the device authorization endpoint.
     * Set to false to disable.
     */
    rateLimit?: Partial<RateLimitOptions> | false;
};

const DeviceAuthorizationRequestSchema = z.object({
    scope: z.string().optional(),
    resource: z.string().url().optional(),
});

export function deviceAuthorizationHandler({ provider, rateLimit: rateLimitConfig }: DeviceAuthorizationHandlerOptions): RequestHandler {
    if (!provider.requestDeviceAuthorization) {
        throw new UnsupportedGrantTypeError('Device authorization is not supported by this authorization server');
    }

    const router = express.Router();

    router.use(allowedMethods(['POST']));
    router.use(express.urlencoded({ extended: false }));

    if (rateLimitConfig !== false) {
        router.use(
            rateLimit({
                windowMs: 15 * 60 * 1000,
                max: 50,
                standardHeaders: true,
                legacyHeaders: false,
                message: new TooManyRequestsError('You have exceeded the rate limit for device authorization requests').toResponseObject(),
                ...rateLimitConfig,
            }),
        );
    }

    router.use(authenticateClient({ clientsStore: provider }));

    router.post('/', async (req, res) => {
        res.setHeader('Cache-Control', 'no-store');

        try {
            const parseResult = DeviceAuthorizationRequestSchema.safeParse(req.body);
            if (!parseResult.success) {
                throw new InvalidRequestError(parseResult.error.message);
            }

            const client = req.client;
            if (!client) {
                throw new ServerError('Internal Server Error');
            }

            const { scope, resource } = parseResult.data;
            const scopes = scope?.split(/\s+/).filter(Boolean);

            const body = await provider.requestDeviceAuthorization!(client, {
                scopes: scopes?.length ? scopes : undefined,
                resource: resource ? new URL(resource) : undefined,
            });

            res.status(200).json(body);
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
