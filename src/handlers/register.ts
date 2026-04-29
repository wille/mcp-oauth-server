import express, { RequestHandler } from 'express';
import { OAuthClientMetadataSchema } from '../schemas.js';
import cors from 'cors';
import { OAuthServer } from '../OAuthServer.js';
import { rateLimit, Options as RateLimitOptions } from 'express-rate-limit';
import { allowedMethods } from '../middleware/allowedMethods.js';
import { InvalidClientMetadataError, ServerError, TooManyRequestsError, OAuthError, UnsupportedGrantTypeError } from '../errors.js';
import { DEVICE_AUTHORIZATION_GRANT_TYPE } from '../deviceFlow.js';

export type ClientRegistrationHandlerOptions = {
    /**
     * OAuth provider used for dynamic client registration.
     */
    provider: OAuthServer;
    /**
     * Rate limiting configuration for the client registration endpoint.
     * Set to false to disable rate limiting for this endpoint.
     * Registration endpoints are particularly sensitive to abuse and should be rate limited.
     */
    rateLimit?: Partial<RateLimitOptions> | false;
};

export function clientRegistrationHandler({ provider, rateLimit: rateLimitConfig }: ClientRegistrationHandlerOptions): RequestHandler {
    if (!provider.registerClient) {
        throw new Error('Client registration store does not support registering clients');
    }

    // Nested router so we can configure middleware and restrict HTTP method
    const router = express.Router();

    // Configure CORS to allow any origin, to make accessible to web-based MCP clients
    router.use(cors());

    router.use(allowedMethods(['POST']));
    router.use(express.json());

    // Apply rate limiting unless explicitly disabled - stricter limits for registration
    if (rateLimitConfig !== false) {
        router.use(
            rateLimit({
                windowMs: 60 * 60 * 1000, // 1 hour
                max: 20, // 20 requests per hour - stricter as registration is sensitive
                standardHeaders: true,
                legacyHeaders: false,
                message: new TooManyRequestsError('You have exceeded the rate limit for client registration requests').toResponseObject(),
                ...rateLimitConfig,
            }),
        );
    }

    router.post('/', async (req, res) => {
        res.setHeader('Cache-Control', 'no-store');

        try {
            const parseResult = OAuthClientMetadataSchema.safeParse(req.body);
            if (!parseResult.success) {
                throw new InvalidClientMetadataError(parseResult.error.message);
            }

            const clientInfo = await provider.registerClient!(parseResult.data);
            res.status(201).json(clientInfo);
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
