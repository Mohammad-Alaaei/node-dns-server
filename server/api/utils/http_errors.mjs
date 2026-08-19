/** Throw-style API error: controllers map `err.status` → JSON. */
export function httpError(message, status = 400) {
    const err = new Error(message);
    err.status = status;
    return err;
}

/**
 * Express async handler: service throws → status JSON or next(err).
 */
export function asyncHandler(fn) {
    return async (req, res, next) => {
        try {
            await fn(req, res, next);
        } catch (err) {
            if (err?.status) {
                return res.status(err.status).json({ error: err.message });
            }
            return next(err);
        }
    };
}

/**
 * Map Sequelize / validation errors to HTTP responses.
 */
export function sendSequelizeError(res, err) {
    if (err?.name === 'SequelizeUniqueConstraintError') {
        const fields = err.errors?.map(e => e.path).filter(Boolean) ?? [];
        const msg = fields.length
            ? `Duplicate value for: ${fields.join(', ')}`
            : 'Duplicate entry';
        return res.status(409).json({
            error: msg,
            fields,
            detail: err.parent?.sqlMessage ?? err.message
        });
    }

    if (err?.name === 'SequelizeForeignKeyConstraintError') {
        return res.status(400).json({
            error: 'Invalid reference (foreign key)',
            detail: err.parent?.sqlMessage ?? err.message
        });
    }

    if (err?.name === 'SequelizeValidationError') {
        return res.status(400).json({
            error: 'Validation failed',
            detail: err.errors?.map(e => e.message) ?? err.message
        });
    }

    return null;
}
