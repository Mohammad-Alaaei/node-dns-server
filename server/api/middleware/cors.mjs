import { config } from '../../../config/config.mjs';

/**
 * Configurable CORS from config.api.cors / .env (API_CORS_*).
 * - origins empty → no CORS headers (same-origin / non-browser clients only)
 * - origins includes "*" → allow any Origin (credentials forced off)
 * - otherwise exact match against request Origin
 */
export function corsMiddleware(req, res, next) {
    const {
        origins,
        credentials,
        methods,
        allowedHeaders,
        maxAge
    } = config.api.cors;

    const requestOrigin = req.headers.origin;

    if (!origins.length) {
        return next();
    }

    const allowAll = origins.includes('*');
    let allowOrigin = null;

    if (allowAll) {
        // Spec: credentialed requests cannot use *
        allowOrigin = credentials && requestOrigin ? requestOrigin : '*';
        if (credentials && requestOrigin) {
            // Reflect origin when credentials + wildcard config
            allowOrigin = requestOrigin;
        } else if (!credentials) {
            allowOrigin = '*';
        }
    } else if (requestOrigin && origins.includes(requestOrigin)) {
        allowOrigin = requestOrigin;
    }

    if (allowOrigin) {
        res.setHeader('Access-Control-Allow-Origin', allowOrigin);
        res.setHeader('Vary', 'Origin');

        const useCredentials = credentials && allowOrigin !== '*';
        if (useCredentials) {
            res.setHeader('Access-Control-Allow-Credentials', 'true');
        }

        res.setHeader('Access-Control-Allow-Methods', methods.join(', '));
        res.setHeader('Access-Control-Allow-Headers', allowedHeaders.join(', '));
        res.setHeader('Access-Control-Max-Age', String(maxAge));
        // So frontend can read Authorization / custom headers if needed
        res.setHeader('Access-Control-Expose-Headers', 'Content-Type');
    }

    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }

    return next();
}
