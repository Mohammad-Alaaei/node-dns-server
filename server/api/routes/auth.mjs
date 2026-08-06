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

        if (!username || !encryptedPassword) {
            return res.status(400).json({ error: 'username and password required' });
        }

        let password;
        try {
            password = decryptPassword(encryptedPassword);
        } catch {
            return res.status(400).json({
                error: 'Invalid encrypted password — fetch /api/auth/public-key and encrypt with RSA-OAEP SHA-256'
            });
        }

        const user = await User.findOne({ where: { username } });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const ok = await verifyPassword(password, user.password_hash);

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
 */
router.post('/users', authenticate, requireRole('superadmin'), async (req, res, next) => {
    try {
        const { username, password, role = 'viewer' } = req.body ?? {};

        if (!username || !password) {
            return res.status(400).json({ error: 'username and password required' });
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
        const password_hash = await hashPassword(password);

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
 * GET /api/auth/users
 */
router.get('/users', authenticate, requireRole('superadmin'), async (req, res, next) => {
    try {
        const users = await User.findAll({
            attributes: PUBLIC_USER_FIELDS,
            order: [['id', 'ASC']]
        });
        return res.json({ users });
    } catch (err) {
        return next(err);
    }
});

export default router;
