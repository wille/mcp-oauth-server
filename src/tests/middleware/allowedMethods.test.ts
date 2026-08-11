import { allowedMethods } from '../../middleware/allowedMethods.js';
import express, { Request, Response } from 'express';
import request from 'supertest';

describe('allowedMethods', () => {
    let app: express.Express;

    beforeEach(() => {
        app = express();

        // Set up a test router with a GET handler and 405 middleware
        const router = express.Router();

        router.get('/test', (req, res) => {
            res.status(200).send('GET success');
        });

        // Add method not allowed middleware for all other methods
        router.all('/test', allowedMethods(['GET']));

        app.use(router);
    });

    test('allows specified HTTP method', async () => {
        const response = await request(app).get('/test');
        expect(response.status).toBe(200);
        expect(response.text).toBe('GET success');
    });

    test('returns 405 for unspecified HTTP methods', async () => {
        const methods = ['post', 'put', 'delete', 'patch'];

        for (const method of methods) {
            const response = await request(app)[method]('/test');
            expect(response.status).toBe(405);
            expect(response.body).toEqual({
                error: 'method_not_allowed',
                error_description: `The method ${method.toUpperCase()} is not allowed for this endpoint`,
            });
        }
    });

    test('includes Allow header with specified methods', async () => {
        const response = await request(app).post('/test');
        expect(response.headers.allow).toBe('GET, HEAD');
    });

    /**
     * RFC 9110 §9.3.2 defines HEAD as GET without a response body, so a resource serving GET
     * serves HEAD. Express already routes it to the GET handler.
     */
    describe('HEAD', () => {
        /**
         * Mounted middleware-first, the way the real handlers do it. The shared `app` above
         * registers its GET route first, so Express answers HEAD from that route and this
         * middleware never sees the request - which would make the assertion vacuous.
         */
        function appWithMiddlewareFirst(methods: string[]): express.Express {
            const local = express();
            const router = express.Router();
            router.use(allowedMethods(methods));
            router.get('/test', (_req: Request, res: Response) => {
                res.status(200).send('GET success');
            });
            local.use(router);
            return local;
        }

        test('is allowed wherever GET is, and returns no body', async () => {
            const response = await request(appWithMiddlewareFirst(['GET'])).head('/test');

            expect(response.status).toBe(200);
            expect(response.text).toBeUndefined();
        });

        test('is named in the Allow header', async () => {
            const response = await request(app).post('/test');

            expect(response.headers.allow).toBe('GET, HEAD');
        });

        test('is still refused where GET is not allowed', async () => {
            const postOnly = express();
            const router = express.Router();
            router.post('/only-post', (_req: Request, res: Response) => {
                res.status(200).send('POST');
            });
            router.all('/only-post', allowedMethods(['POST']));
            postOnly.use(router);

            const response = await request(postOnly).head('/only-post');

            expect(response.status).toBe(405);
            expect(response.headers.allow).toBe('POST');
        });
    });

    test('still refuses OPTIONS, leaving CORS to the application', async () => {
        const response = await request(app).options('/test');

        expect(response.status).toBe(405);
    });

    test('works with multiple allowed methods', async () => {
        const multiMethodApp = express();
        const router = express.Router();

        router.get('/multi', (req: Request, res: Response) => {
            res.status(200).send('GET');
        });
        router.post('/multi', (req: Request, res: Response) => {
            res.status(200).send('POST');
        });
        router.all('/multi', allowedMethods(['GET', 'POST']));

        multiMethodApp.use(router);

        // Allowed methods should work
        const getResponse = await request(multiMethodApp).get('/multi');
        expect(getResponse.status).toBe(200);

        const postResponse = await request(multiMethodApp).post('/multi');
        expect(postResponse.status).toBe(200);

        // Unallowed methods should return 405
        const putResponse = await request(multiMethodApp).put('/multi');
        expect(putResponse.status).toBe(405);
        // HEAD is listed next to the GET it follows from, not appended at the end.
        expect(putResponse.headers.allow).toBe('GET, HEAD, POST');
    });
});
