/**
 * Console-only HTTP access log for every request.
 * Format: METHOD path status durationMs ip
 */
export function requestLogger(req, res, next) {
    const start = Date.now();

    res.on('finish', () => {
        const ms = Date.now() - start;
        const ip = req.ip || req.socket?.remoteAddress || '-';
        console.log(
            `[HTTP] ${req.method} ${req.originalUrl} ${res.statusCode} ${ms}ms ${ip}`
        );
    });

    next();
}
