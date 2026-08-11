import { RequestHandler } from 'express';
import { MethodNotAllowedError } from '../errors.js';

/**
 * Middleware to handle unsupported HTTP methods with a 405 Method Not Allowed response.
 *
 * `HEAD` is accepted wherever `GET` is. RFC 9110 §9.3.2 defines it as identical to `GET` except
 * that the response carries no body, so a resource serving `GET` serves `HEAD` by definition -
 * and Express already routes `HEAD` to `GET` handlers and strips the body. Rejecting it made the
 * discovery endpoints answer 405 to the health checks, uptime monitors and cache validators that
 * reach for `HEAD` first.
 *
 * `OPTIONS` is still refused. Answering it usefully means taking a position on CORS, which
 * depends on where a deployment puts its authorization server relative to its clients; mount
 * `cors()` ahead of the router if you need preflight to succeed.
 *
 * @param allowedMethods Array of allowed HTTP methods for this endpoint (e.g., ['GET', 'POST'])
 * @returns Express middleware that returns a 405 error if method not in allowed list
 */
export function allowedMethods(allowedMethods: string[]): RequestHandler {
    const methods = [...allowedMethods];
    const getIndex = methods.indexOf('GET');
    if (getIndex !== -1 && !methods.includes('HEAD')) {
        methods.splice(getIndex + 1, 0, 'HEAD');
    }

    return (req, res, next) => {
        if (methods.includes(req.method)) {
            next();
            return;
        }

        // RFC 9110 §10.2.1: Allow lists the methods the resource actually supports, so it has to
        // name HEAD too.
        const error = new MethodNotAllowedError(`The method ${req.method} is not allowed for this endpoint`);
        res.status(405).set('Allow', methods.join(', ')).json(error.toResponseObject());
    };
}
