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

/**
 * Marks a pending device authorization as approved by the signed-in user.
 *
 * `user_code` is read from the request body only. It is a credential - whoever presents it
 * decides which pending authorization gets bound to their account - and query strings end up in
 * access logs, `Referer` headers, browser history and error trackers, none of which see bodies.
 *
 * **This route needs CSRF protection, and the library cannot provide it.** Approval is a state
 * change whose acting identity comes from {@link ApproveDeviceAuthorizationHandlerOptions.getUser},
 * meaning a session your application owns. Restricting the route to POST means `SameSite=Lax`
 * and `Strict` cookies are not sent on a cross-site form submission, which covers most
 * deployments - but this library cannot see how your session cookie is configured, and cookies
 * with no explicit `SameSite` attribute are exempted from that protection for a couple of
 * minutes by some browsers. Mount your own CSRF middleware ahead of this handler, and have your
 * approval page submit the token it issues.
 */
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
            const parseResult = DeviceAuthorizationApprovalSchema.safeParse(req.body);
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
