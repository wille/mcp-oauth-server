import express, { RequestHandler } from 'express';
import { OAuthMetadata, OAuthProtectedResourceMetadata } from '../schemas.js';
import { allowedMethods } from '../middleware/allowedMethods.js';

export function metadataHandler(metadata: OAuthMetadata | OAuthProtectedResourceMetadata): RequestHandler {
    // Nested router so we can configure middleware and restrict HTTP method
    const router = express.Router();

    router.use(allowedMethods(['GET']));
    router.get('/', (req, res) => {
        res.status(200).json(metadata);
    });

    return router;
}
