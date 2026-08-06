import { Router } from 'express';
import { User } from '../../../database/models/index.mjs';
import { hashPassword, verifyPassword } from '../auth/password.mjs';
import {
    signAccessToken,
    issueRefreshToken,
    rotateRefreshToken,
    revokeRefreshToken,
    accessTokenMeta
} from '../auth/jwt.mjs';
import { getPublicKeyPem, decryptPassword } from '../auth/crypto.mjs';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { paginateQuery } from '../utils/pagination.mjs';

const router = Router();

const PUBLIC_USER_FIELDS = ['id', 'username', 'role', 'created_at', 'updated_at'];

function clearAuthCookies(res) {
    const clear = 'Path=/; Max-Age=0; HttpOnly; SameSite=Strict';
    res.setHeader('Set-Cookie', [
        `token=; ${clear}`,
        `accessToken=; ${clear}`,
        `refreshToken=; ${clear}`,
        `Authorization=; ${clear}`
    ]);
}

function tokenPairResponse(user, accessToken, refresh) {
    const meta = accessTokenMeta();
    return {
        accessToken,
        refreshToken: refresh.refreshToken,
        expiresIn: meta.expiresIn,
        refreshExpiresIn: refresh.refreshExpiresIn,
        refreshExpiresAt: refresh.refreshExpiresAt,
        user: {
            id: user.id,
            username: user.username,
            role: user.role
        }
    };
}

/**
 * Decrypt RSA-OAEP password ciphertext from the client.
 * Returns { password } or { error, status } for the caller to send.
 */
function resolveEncryptedPassword(encryptedPassword) {
    if (!encryptedPassword || typeof encryptedPassword !== 'string') {
        return {
            error: 'password required (base64 RSA-OAEP ciphertext from /api/auth/public-key)',
            status: 400
        };
    }

    try {
        return { password: decryptPassword(encryptedPassword) };
    } catch {
        return {
            error: 'Invalid encrypted password — fetch /api/auth/public-key and encrypt with RSA-OAEP SHA-256',
            status: 400
        };
    }
}

/**
 * GET /api/auth/public-key
 */
router.get('/public-key', (_req, res) => {
    res.json({
        algorithm: 'RSA-OAEP',
        hash: 'SHA-256',
        publicKey: getPublicKeyPem()
    });
});

/**
 * POST /api/auth/login
 * Body: { username, password } — password = base64 RSA-OAEP ciphertext
 * Returns accessToken (short JWT) + refreshToken (opaque, stored hashed in DB)
 */
router.post('/login', async (req, res, next) => {
    try {
        const { username, password: encryptedPassword } = req.body ?? {};

        if (!username) {
            return res.status(400).json({ error: 'username and password required' });
        }

        const resolved = resolveEncryptedPassword(encryptedPassword);
        if (resolved.error) {
            return res.status(resolved.status).json({ error: resolved.error });
        }

        const user = await User.findOne({ where: { username } });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const ok = await verifyPassword(resolved.password, user.password_hash);

        if (!ok) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const accessToken = signAccessToken(user);
        const refresh = await issueRefreshToken(user.id);

        return res.json(tokenPairResponse(user, accessToken, refresh));
    } catch (err) {
        return next(err);
    }
});

/**
 * POST /api/auth/refresh
 * Body: { refreshToken }
 * Rotates refresh token and returns a new access + refresh pair.
 */
router.post('/refresh', async (req, res, next) => {
    try {
        const refreshToken =
            req.body?.refreshToken ||
            req.headers['x-refresh-token'];

        if (!refreshToken) {
            return res.status(400).json({ error: 'refreshToken required' });
        }

        const rotated = await rotateRefreshToken(refreshToken);

        if (!rotated) {
            return res.status(401).json({ error: 'Invalid or expired refresh token' });
        }

        const accessToken = signAccessToken(rotated.user);

        return res.json(tokenPairResponse(rotated.user, accessToken, {
            refreshToken: rotated.refreshToken,
            refreshExpiresIn: rotated.refreshExpiresIn,
            refreshExpiresAt: rotated.refreshExpiresAt
        }));
    } catch (err) {
        return next(err);
    }
});

/**
 * POST /api/auth/logout
 * Body: { refreshToken } (or header X-Refresh-Token)
 * Revokes the refresh token in DB so it cannot mint new access tokens.
 * Access token is not required (may already be expired). Clears auth cookies.
 */
router.post('/logout', async (req, res, next) => {
    try {
        const refreshToken =
            req.body?.refreshToken ||
            req.headers['x-refresh-token'];

        if (refreshToken) {
            await revokeRefreshToken(refreshToken);
        }

        clearAuthCookies(res);

        return res.json({
            ok: true,
            message: 'Logged out'
        });
    } catch (err) {
        return next(err);
    }
});

/**
 * GET /api/auth/me
 */
router.get('/me', authenticate, (req, res) => {
    res.json({ user: req.user });
});

/**
 * POST /api/auth/users
 * superadmin only
 * Body: { username, password, role? }
 * `password` MUST be base64 RSA-OAEP ciphertext (same as login).
 * Server decrypts → bcrypt hash → store (plaintext never written to DB).
 */
router.post('/users', authenticate, requireRole('superadmin'), async (req, res, next) => {
    try {
        const { username, password: encryptedPassword, role = 'viewer' } = req.body ?? {};

        if (!username) {
            return res.status(400).json({ error: 'username and password required' });
        }

        const resolved = resolveEncryptedPassword(encryptedPassword);
        if (resolved.error) {
            return res.status(resolved.status).json({ error: resolved.error });
        }

        const allowed = ['superadmin', 'admin', 'viewer'];
        if (!allowed.includes(role)) {
            return res.status(400).json({ error: `role must be one of: ${allowed.join(', ')}` });
        }

        const existing = await User.findOne({ where: { username } });
        if (existing) {
            return res.status(409).json({ error: 'username already taken' });
        }

        const now = Date.now();
        const password_hash = await hashPassword(resolved.password);

        const user = await User.create({
            username,
            password_hash,
            role,
            created_at: now,
            updated_at: now
        });

        return res.status(201).json({
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                created_at: user.created_at,
                updated_at: user.updated_at
            }
        });
    } catch (err) {
        return next(err);
    }
});

/**
 * GET /api/auth/users?page=1&limit=20
 */
router.get('/users', authenticate, requireRole('superadmin'), async (req, res, next) => {
    try {
        const result = await paginateQuery(req.query, ({ limit, offset }) =>
            User.findAndCountAll({
                attributes: PUBLIC_USER_FIELDS,
                order: [['id', 'ASC']],
                limit,
                offset
            })
        );

        return res.json(result);
    } catch (err) {
        return next(err);
    }
});

export default router;
