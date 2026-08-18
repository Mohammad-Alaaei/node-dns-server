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
import { listQuery } from '../utils/list_query.mjs';
import authController from '../controllers/AuthController.mjs';
import { nextRouter } from '../middleware/nextRouter.mjs';

const router = Router();

/**
 * GET /api/auth/public-key
 */
router.get('/public-key', authController.getPublicKey, nextRouter);

/**
 * POST /api/auth/login
 * Body: { username, password } — password = base64 RSA-OAEP ciphertext
 * Returns accessToken (short JWT) + refreshToken (opaque, stored hashed in DB)
 */
router.post('/login', authController.login, nextRouter);

/**
 * POST /api/auth/refresh
 * Body: { refreshToken }
 * Rotates refresh token and returns a new access + refresh pair.
 */
router.post('/refresh', authController.refreshToken, nextRouter);

/**
 * POST /api/auth/logout
 * Body: { refreshToken } (or header X-Refresh-Token)
 * Revokes the refresh token in DB so it cannot mint new access tokens.
 * Access token is not required (may already be expired). Clears auth cookies.
 */
router.post('/logout', authController.logout, nextRouter);

/**
 * GET /api/auth/me
 */
router.get('/me', authenticate, authController.me, nextRouter);

/**
 * POST /api/auth/users
 * superadmin only
 * Body: { username, password, role? }
 * `password` MUST be base64 RSA-OAEP ciphertext (same as login).
 * Server decrypts → bcrypt hash → store (plaintext never written to DB).
 */
router.post('/users', authenticate, requireRole('superadmin'), authController.createUser, nextRouter);

/**
 * GET /api/auth/users?page=1&limit=20
 *   &searchField=username&search=admin
 *   &filter[role]=viewer&filterLogic=AND
 *   &sortBy=username&sortDir=ASC
 */
router.get('/users', authenticate, requireRole('superadmin'), authController.getUsers, nextRouter);

export default router;
