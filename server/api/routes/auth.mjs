import { Router } from 'express';
import { authenticate, requireRole } from '../middleware/auth.mjs';
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
 */
router.post('/login', authController.login, nextRouter);

/**
 * POST /api/auth/refresh
 * Body: { refreshToken }
 */
router.post('/refresh', authController.refreshToken, nextRouter);

/**
 * POST /api/auth/logout
 * Body: { refreshToken } (or header X-Refresh-Token)
 */
router.post('/logout', authController.logout, nextRouter);

/**
 * GET /api/auth/me
 */
router.get('/me', authenticate, authController.me, nextRouter);

/**
 * POST /api/auth/change-password
 * Any authenticated user — change own password.
 * Body: { currentPassword, newPassword } — both RSA-OAEP ciphertext
 * Revokes all refresh tokens for this user.
 */
router.post(
    '/change-password',
    authenticate,
    authController.changeOwnPassword,
    nextRouter
);

/**
 * POST /api/auth/users
 * superadmin only — create user
 * Body: { username, password, role? }
 */
router.post(
    '/users',
    authenticate,
    requireRole('superadmin'),
    authController.createUser,
    nextRouter
);

/**
 * GET /api/auth/users
 * superadmin + admin — list (no password fields)
 */
router.get(
    '/users',
    authenticate,
    requireRole('superadmin', 'admin'),
    authController.getUsers,
    nextRouter
);

/**
 * GET /api/auth/users/:id
 * superadmin + admin
 */
router.get(
    '/users/:id',
    authenticate,
    requireRole('superadmin', 'admin'),
    authController.getUser,
    nextRouter
);

/**
 * PATCH /api/auth/users/:id
 * superadmin + admin — edit username / role / enabled
 * Body: { username?, role?, enabled? }
 * Admin cannot manage superadmin targets.
 * Superadmin role cannot be changed on any superadmin account.
 */
router.patch(
    '/users/:id',
    authenticate,
    requireRole('superadmin', 'admin'),
    authController.updateUser,
    nextRouter
);

/**
 * POST /api/auth/users/:id/password
 * superadmin + admin — set password for non-superadmin users only
 * Body: { password } — RSA-OAEP ciphertext
 * Superadmin password: POST /change-password only (self).
 * Revokes all refresh tokens for that user.
 */
router.post(
    '/users/:id/password',
    authenticate,
    requireRole('superadmin', 'admin'),
    authController.setUserPassword,
    nextRouter
);

/**
 * DELETE /api/auth/users/:id
 * superadmin + admin — soft delete (sets deleted_at, enabled=false)
 */
router.delete(
    '/users/:id',
    authenticate,
    requireRole('superadmin', 'admin'),
    authController.softDeleteUser,
    nextRouter
);

export default router;
