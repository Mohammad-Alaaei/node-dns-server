import { verifyAccessToken } from '../auth/jwt.mjs';
import { User } from '../../../database/models/index.mjs';

/**
 * Require a valid access JWT. Attaches `req.user` = { id, username, role }.
 */
export function authenticate(req, res, next) {
    const header = req.headers.authorization;

    if (!header || !header.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing or invalid Authorization header' });
    }

    const token = header.slice(7);

    try {
        const payload = verifyAccessToken(token);
        req.user = {
            id: payload.sub,
            username: payload.username,
            role: payload.role
        };
        return next();
    } catch {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

/**
 * After `authenticate`. Allows only the listed roles.
 * Usage: requireRole('superadmin') or requireRole('superadmin', 'admin')
 */
export function requireRole(...roles) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Unauthenticated' });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Forbidden' });
        }

        return next();
    };
}

/**
 * Optional: load full user row from DB (e.g. if role may have changed).
 * Not used on every request by default — JWT role is enough for now.
 */
export async function loadUser(req, res, next) {
    try {
        const row = await User.findByPk(req.user.id, {
            attributes: ['id', 'username', 'role']
        });

        if (!row) {
            return res.status(401).json({ error: 'User no longer exists' });
        }

        req.user = {
            id: row.id,
            username: row.username,
            role: row.role
        };
        return next();
    } catch (err) {
        return next(err);
    }
}
