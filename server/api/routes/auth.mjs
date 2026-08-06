import { Router } from 'express';
import { User } from '../../../database/models/index.mjs';
import { hashPassword, verifyPassword } from '../auth/password.mjs';
import { signToken } from '../auth/jwt.mjs';
import { getPublicKeyPem, decryptPassword } from '../auth/crypto.mjs';
import { authenticate, requireRole } from '../middleware/auth.mjs';

const router = Router();

const PUBLIC_USER_FIELDS = ['id', 'username', 'role', 'created_at', 'updated_at'];

/**
 * GET /api/auth/public-key
 * Client fetches this, encrypts the password with RSA-OAEP (SHA-256),
 * then sends the base64 ciphertext as `password` on login.
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
 * Body: { username, password }
 * `password` MUST be base64 RSA-OAEP ciphertext of the real password
 * (encrypted with the public key from /api/auth/public-key).
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

        const token = signToken(user);

        return res.json({
            token,
            expiresIn: process.env.API_JWT_EXPIRES_IN ?? '15m',
            user: {
                id: user.id,
                username: user.username,
                role: user.role
            }
        });
    } catch (err) {
        return next(err);
    }
});

/**
 * POST /api/auth/logout
 * Verifies the current Bearer token. No server-side blacklist (short-lived tokens).
 * Returns success + Set-Cookie headers so the client can clear any auth cookie.
 */
router.post('/logout', authenticate, (req, res) => {
    // Clear common auth cookie names if the frontend stores the token in a cookie
    const clear = 'Path=/; Max-Age=0; HttpOnly; SameSite=Strict';
    res.setHeader('Set-Cookie', [
        `token=; ${clear}`,
        `accessToken=; ${clear}`,
        `Authorization=; ${clear}`
    ]);

    res.json({
        ok: true,
        message: 'Logged out',
        user: req.user
    });
});

/**
 * GET /api/auth/me
 */
router.get('/me', authenticate, (req, res) => {
    res.json({ user: req.user });
});

/**
 * POST /api/auth/users
 * Body: { username, password, role? }
 * Password here is PLAINTEXT (admin-to-server over TLS only) — same as bootstrap.
 * Encrypt-on-wire is required for the public login endpoint only.
 * superadmin only. Default role = viewer.
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
 * superadmin only — list users (no password hashes).
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
