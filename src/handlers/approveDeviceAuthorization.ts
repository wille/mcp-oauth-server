import express, { RequestHandler } from 'express';
import * as z from 'zod/v4';
import { rateLimit, Options as RateLimitOptions } from 'express-rate-limit';
import { OAuthServer } from '../OAuthServer.js';
import { allowedMethods } from '../middleware/allowedMethods.js';
import { InvalidRequestError, OAuthError, ServerError, TooManyRequestsError } from '../errors.js';

export type ApproveDeviceAuthorizationHandlerOptions = {
    provider: OAuthServer;
    /**
     * Rate limiting for the device approval endpoint.
     * Set to false to disable.
     */
    rateLimit?: Partial<RateLimitOptions> | false;
    /**
     * Extract authenticated user id from the request.
     */
    getUser: (req: express.Request) => Promise<string> | string;
};

const DeviceAuthorizationApprovalSchema = z.object({
    user_code: z.string().min(1),
});

export function approveDeviceAuthorizationHandler({
    provider,
    rateLimit: rateLimitConfig,
    getUser,
}: ApproveDeviceAuthorizationHandlerOptions): RequestHandler {
    const router = express.Router();
    router.use(allowedMethods(['POST']));
    router.use(express.urlencoded({ extended: false }));
    router.use(express.json());

    if (rateLimitConfig !== false) {
        router.use(
            rateLimit({
                windowMs: 15 * 60 * 1000,
                max: 20,
                standardHeaders: true,
                legacyHeaders: false,
                message: new TooManyRequestsError(
                    'You have exceeded the rate limit for device authorization approval requests',
                ).toResponseObject(),
                ...rateLimitConfig,
            }),
        );
    }

    router.post('/', async (req, res) => {
        try {
            const merged = { ...req.query, ...req.body };
            const parseResult = DeviceAuthorizationApprovalSchema.safeParse(merged);
            if (!parseResult.success) {
                throw new InvalidRequestError(parseResult.error.message);
            }

            const userId = await getUser(req);
            if (!userId) {
                throw new ServerError('Invalid user');
            }

            await provider.approveDeviceAuthorization(parseResult.data.user_code, userId);
            res.status(200).json({ ok: true });
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
