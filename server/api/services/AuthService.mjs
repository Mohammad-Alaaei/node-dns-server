import { Op } from 'sequelize';
import { User } from '../../../database/models/index.mjs';
import { decryptPassword, getPublicKeyPem } from '../auth/crypto.mjs';
import {
    accessTokenMeta,
    issueRefreshToken,
    revokeRefreshToken,
    revokeAllRefreshTokensForUser,
    rotateRefreshToken,
    signAccessToken
} from '../auth/jwt.mjs';
import { hashPassword, verifyPassword } from '../auth/password.mjs';
import { listQuery } from '../utils/list_query.mjs';

const PUBLIC_USER_FIELDS = [
    'id',
    'username',
    'role',
    'enabled',
    'deleted_at',
    'created_at',
    'updated_at'
];

const USERS_LIST_SCHEMA = {
    searchable: ['username', 'role'],
    filterable: ['id', 'username', 'role', 'enabled'],
    sortable: [
        'id',
        'username',
        'role',
        'enabled',
        'deleted_at',
        'created_at',
        'updated_at'
    ],
    defaultSort: ['id', 'ASC'],
    fieldTypes: {
        id: 'number',
        enabled: 'boolean',
        deleted_at: 'number',
        created_at: 'number',
        updated_at: 'number'
    }
};

const ASSIGNABLE_ROLES = ['superadmin', 'admin', 'viewer'];

function httpError(message, status = 400) {
    const err = new Error(message);
    err.status = status;
    return err;
}

function publicUser(user) {
    const u = user.get ? user.get({ plain: true }) : user;
    return {
        id: u.id,
        username: u.username,
        role: u.role,
        enabled: u.enabled !== false,
        deleted_at: u.deleted_at ?? null,
        created_at: u.created_at,
        updated_at: u.updated_at
    };
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
            role: user.role,
            enabled: user.enabled !== false
        }
    };
}

/**
 * Decrypt RSA-OAEP password ciphertext.
 */
function resolveEncryptedPassword(encryptedPassword) {
    if (!encryptedPassword || typeof encryptedPassword !== 'string') {
        throw httpError(
            'password required (base64 RSA-OAEP ciphertext from /api/auth/public-key)',
            400
        );
    }

    try {
        return decryptPassword(encryptedPassword);
    } catch {
        throw httpError(
            'Invalid encrypted password — fetch /api/auth/public-key and encrypt with RSA-OAEP SHA-256',
            400
        );
    }
}

function isSystemUser(user) {
    return !user || user.role === 'system' || user.id === 0;
}

function assertCanManageTarget(actor, target) {
    if (isSystemUser(target)) {
        throw httpError('Cannot manage system user', 403);
    }

    // Admin cannot touch superadmin accounts
    if (actor.role === 'admin' && target.role === 'superadmin') {
        throw httpError('Forbidden', 403);
    }
}

/** Superadmin role is immutable via admin APIs. */
function assertRoleNotLocked(target) {
    if (target.role === 'superadmin') {
        throw httpError(
            'Cannot change role of a superadmin',
            403
        );
    }
}

/**
 * Superadmin password can only be changed via POST /change-password (self).
 * No admin/set-password endpoint may reset it.
 */
function assertPasswordNotLocked(target) {
    if (target.role === 'superadmin') {
        throw httpError(
            'Cannot reset superadmin password — use change-password while logged in as that user',
            403
        );
    }
}

class AuthService {
    getPublicKey() {
        return {
            algorithm: 'RSA-OAEP',
            hash: 'SHA-256',
            publicKey: getPublicKeyPem()
        };
    }

    async login({ username, encryptedPassword }) {
        if (!username) {
            throw httpError('username and password required', 400);
        }

        const password = resolveEncryptedPassword(encryptedPassword);

        const user = await User.findOne({ where: { username } });

        if (isSystemUser(user)) {
            throw httpError('Invalid credentials', 401);
        }

        if (user.deleted_at != null) {
            throw httpError('Invalid credentials', 401);
        }

        if (user.enabled === false) {
            throw httpError('Account disabled', 403);
        }

        const ok = await verifyPassword(password, user.password_hash);
        if (!ok) {
            throw httpError('Invalid credentials', 401);
        }

        const accessToken = signAccessToken(user);
        const refresh = await issueRefreshToken(user.id);

        return tokenPairResponse(user, accessToken, refresh);
    }

    async refreshToken(refreshToken) {
        if (!refreshToken) {
            throw httpError('refreshToken required', 400);
        }

        const rotated = await rotateRefreshToken(refreshToken);

        if (!rotated) {
            throw httpError('Invalid or expired refresh token', 401);
        }

        const user = rotated.user;
        if (
            isSystemUser(user) ||
            user.deleted_at != null ||
            user.enabled === false
        ) {
            await revokeAllRefreshTokensForUser(user.id);
            throw httpError('Invalid or expired refresh token', 401);
        }

        const accessToken = signAccessToken(user);

        return tokenPairResponse(user, accessToken, {
            refreshToken: rotated.refreshToken,
            refreshExpiresIn: rotated.refreshExpiresIn,
            refreshExpiresAt: rotated.refreshExpiresAt
        });
    }

    async logout(refreshToken) {
        if (refreshToken) {
            await revokeRefreshToken(refreshToken);
        }
        return { ok: true, message: 'Logged out' };
    }

    me(user) {
        // JWT payload only — no password fields ever
        return {
            user: {
                id: user.id,
                username: user.username,
                role: user.role
            }
        };
    }

    async createUser({ username, encryptedPassword, role = 'viewer' }) {
        if (!username) {
            throw httpError('username and password required', 400);
        }

        const password = resolveEncryptedPassword(encryptedPassword);

        if (!ASSIGNABLE_ROLES.includes(role)) {
            throw httpError(
                `role must be one of: ${ASSIGNABLE_ROLES.join(', ')}`,
                400
            );
        }

        const existing = await User.findOne({ where: { username } });
        if (existing) {
            throw httpError('username already taken', 409);
        }

        const now = Date.now();
        const password_hash = await hashPassword(password);

        const user = await User.create({
            username,
            password_hash,
            role,
            enabled: true,
            deleted_at: null,
            created_at: now,
            updated_at: now
        });

        return { user: publicUser(user) };
    }

    async getUsers(query) {
        // Exclude system user; include soft-deleted unless filtered out by client
        const result = await listQuery(
            query,
            {
                ...USERS_LIST_SCHEMA,
                baseWhere: {
                    id: { [Op.ne]: 0 },
                    role: { [Op.ne]: 'system' }
                }
            },
            ({ where, order, limit, offset }) =>
                User.findAndCountAll({
                    attributes: PUBLIC_USER_FIELDS,
                    where,
                    order,
                    limit,
                    offset
                })
        );

        if (result.error) {
            throw httpError(result.error, result.status ?? 400);
        }

        result.items = result.items.map(row => publicUser(row));
        return result;
    }

    async getUserById(rawId, actor) {
        const id = Number.parseInt(String(rawId), 10);
        if (!Number.isFinite(id) || id < 1) {
            throw httpError('invalid id', 400);
        }

        const user = await User.findByPk(id, {
            attributes: PUBLIC_USER_FIELDS
        });

        if (!user || isSystemUser(user)) {
            throw httpError('User not found', 404);
        }

        assertCanManageTarget(actor, user);
        return { user: publicUser(user) };
    }

    /**
     * PATCH user: username?, role?, enabled?
     * Admin cannot assign superadmin or edit superadmin targets.
     */
    async updateUser(actor, rawId, body = {}) {
        const id = Number.parseInt(String(rawId), 10);
        if (!Number.isFinite(id) || id < 1) {
            throw httpError('invalid id', 400);
        }

        const user = await User.findByPk(id);
        if (!user || isSystemUser(user)) {
            throw httpError('User not found', 404);
        }

        assertCanManageTarget(actor, user);

        const updates = { updated_at: Date.now() };

        if (body.username !== undefined) {
            if (typeof body.username !== 'string' || !body.username.trim()) {
                throw httpError('username must be a non-empty string', 400);
            }
            const username = body.username.trim();
            const clash = await User.findOne({
                where: {
                    username,
                    id: { [Op.ne]: id }
                }
            });
            if (clash) {
                throw httpError('username already taken', 409);
            }
            updates.username = username;
        }

        if (body.role !== undefined) {
            if (actor.id === id) {
                throw httpError('Cannot change your own role', 403);
            }
            // Superadmin role is locked
            assertRoleNotLocked(user);

            if (!ASSIGNABLE_ROLES.includes(body.role)) {
                throw httpError(
                    `role must be one of: ${ASSIGNABLE_ROLES.join(', ')}`,
                    400
                );
            }
            if (actor.role === 'admin' && body.role === 'superadmin') {
                throw httpError('Forbidden', 403);
            }
            updates.role = body.role;
        }

        if (body.enabled !== undefined) {
            if (typeof body.enabled !== 'boolean') {
                throw httpError('enabled must be a boolean', 400);
            }
            if (actor.id === id) {
                throw httpError('Cannot enable/disable your own account', 403);
            }
            // Superadmin accounts can never be disabled
            if (user.role === 'superadmin' && body.enabled === false) {
                throw httpError('Cannot disable a superadmin account', 403);
            }
            updates.enabled = body.enabled;
        }

        try {
            await user.update(updates);
        } catch (err) {
            if (err?.name === 'SequelizeUniqueConstraintError') {
                throw httpError('username already taken', 409);
            }
            throw err;
        }

        // Kill sessions if disabled
        if (updates.enabled === false) {
            await revokeAllRefreshTokensForUser(id);
        }

        await user.reload();
        return { user: publicUser(user) };
    }

    /**
     * Soft delete — sets deleted_at, disables account, revokes refresh tokens.
     */
    async softDeleteUser(actor, rawId) {
        const id = Number.parseInt(String(rawId), 10);
        if (!Number.isFinite(id) || id < 1) {
            throw httpError('invalid id', 400);
        }

        if (actor.id === id) {
            throw httpError('Cannot delete your own account', 400);
        }

        const user = await User.findByPk(id);
        if (!user || isSystemUser(user)) {
            throw httpError('User not found', 404);
        }

        if (user.deleted_at != null) {
            throw httpError('User already deleted', 409);
        }

        assertCanManageTarget(actor, user);

        if (user.role === 'superadmin') {
            const otherSupers = await User.count({
                where: {
                    id: { [Op.ne]: id },
                    role: 'superadmin',
                    deleted_at: null
                }
            });
            if (otherSupers < 1) {
                throw httpError('Cannot delete the last superadmin', 400);
            }
        }

        const now = Date.now();
        await user.update({
            deleted_at: now,
            enabled: false,
            updated_at: now
        });

        await revokeAllRefreshTokensForUser(id);

        return { ok: true, user: publicUser(user) };
    }

    /**
     * Admin sets a new password for a user (no current password required).
     * Password must be RSA-encrypted ciphertext.
     */
    async setUserPassword(actor, rawId, encryptedPassword) {
        const id = Number.parseInt(String(rawId), 10);
        if (!Number.isFinite(id) || id < 1) {
            throw httpError('invalid id', 400);
        }

        const user = await User.findByPk(id);
        if (!user || isSystemUser(user)) {
            throw httpError('User not found', 404);
        }

        if (user.deleted_at != null) {
            throw httpError('User is deleted', 400);
        }

        if (actor.id === id) {
            throw httpError(
                'Cannot reset your own password here — use change-password',
                403
            );
        }

        assertCanManageTarget(actor, user);
        assertPasswordNotLocked(user);

        const password = resolveEncryptedPassword(encryptedPassword);
        if (typeof password !== 'string' || password.length < 1) {
            throw httpError('password required', 400);
        }

        const password_hash = await hashPassword(password);
        await user.update({
            password_hash,
            updated_at: Date.now()
        });

        await revokeAllRefreshTokensForUser(id);

        return { ok: true };
    }

    /**
     * Authenticated user changes own password.
     * Body: { currentPassword, newPassword } — both RSA-encrypted.
     */
    async changeOwnPassword(actor, { currentPassword, newPassword }) {
        const user = await User.findByPk(actor.id);
        if (!user || isSystemUser(user) || user.deleted_at != null) {
            throw httpError('User not found', 404);
        }

        if (user.enabled === false) {
            throw httpError('Account disabled', 403);
        }

        const current = resolveEncryptedPassword(currentPassword);
        const next = resolveEncryptedPassword(newPassword);

        if (typeof next !== 'string' || next.length < 1) {
            throw httpError('new password required', 400);
        }

        const ok = await verifyPassword(current, user.password_hash);
        if (!ok) {
            throw httpError('Current password is incorrect', 400);
        }

        const password_hash = await hashPassword(next);
        await user.update({
            password_hash,
            updated_at: Date.now()
        });

        await revokeAllRefreshTokensForUser(user.id);

        return { ok: true, message: 'Password updated' };
    }
}

export default new AuthService();
