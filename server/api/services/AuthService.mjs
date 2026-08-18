import { User } from '../../../database/models/index.mjs';
import { decryptPassword, getPublicKeyPem } from '../auth/crypto.mjs';
import { accessTokenMeta, issueRefreshToken, revokeRefreshToken, rotateRefreshToken, signAccessToken } from '../auth/jwt.mjs';
import { hashPassword, verifyPassword } from '../auth/password.mjs';
import { listQuery } from '../utils/list_query.mjs';


const PUBLIC_USER_FIELDS = ['id', 'username', 'role', 'created_at', 'updated_at'];

const USERS_LIST_SCHEMA = {
    searchable: ['username', 'role'],
    filterable: ['id', 'username', 'role'],
    sortable: ['id', 'username', 'role', 'created_at', 'updated_at'],
    defaultSort: ['id', 'ASC'],
    fieldTypes: {
        id: 'number',
        created_at: 'number',
        updated_at: 'number'
    }
};

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
 * Decrypt RSA-OAEP password ciphertext.
 * Returns { password } or throws an error object { message, status }.
 */
function resolveEncryptedPassword(encryptedPassword) {
    if (!encryptedPassword || typeof encryptedPassword !== 'string') {
        const err = new Error('password required (base64 RSA-OAEP ciphertext from /api/auth/public-key)');
        err.status = 400;
        throw err;
    }

    try {
        return decryptPassword(encryptedPassword);
    } catch {
        const err = new Error(
            'Invalid encrypted password — fetch /api/auth/public-key and encrypt with RSA-OAEP SHA-256'
        );
        err.status = 400;
        throw err;
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
            const err = new Error('username and password required');
            err.status = 400;
            throw err;
        }

        const password = resolveEncryptedPassword(encryptedPassword);

        const user = await User.findOne({ where: { username } });

        if (!user || user.role === 'system' || user.id === 0) {
            const err = new Error('Invalid credentials');
            err.status = 401;
            throw err;
        }

        const ok = await verifyPassword(password, user.password_hash);
        if (!ok) {
            const err = new Error('Invalid credentials');
            err.status = 401;
            throw err;
        }

        const accessToken = signAccessToken(user);
        const refresh = await issueRefreshToken(user.id);

        return tokenPairResponse(user, accessToken, refresh);
    }

    async refreshToken(refreshToken) {
        if (!refreshToken) {
            const err = new Error('refreshToken required');
            err.status = 400;
            throw err;
        }

        const rotated = await rotateRefreshToken(refreshToken);

        if (!rotated) {
            const err = new Error('Invalid or expired refresh token');
            err.status = 401;
            throw err;
        }

        const accessToken = signAccessToken(rotated.user);

        return tokenPairResponse(rotated.user, accessToken, {
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
        return { user };
    }

    async createUser({ username, encryptedPassword, role = 'viewer' }) {
        if (!username) {
            const err = new Error('username and password required');
            err.status = 400;
            throw err;
        }

        const password = resolveEncryptedPassword(encryptedPassword);

        const allowed = ['superadmin', 'admin', 'viewer'];
        if (!allowed.includes(role)) {
            const err = new Error(`role must be one of: ${allowed.join(', ')}`);
            err.status = 400;
            throw err;
        }

        const existing = await User.findOne({ where: { username } });
        if (existing) {
            const err = new Error('username already taken');
            err.status = 409;
            throw err;
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

        return {
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                created_at: user.created_at,
                updated_at: user.updated_at
            }
        };
    }

    async getUsers(query) {
        const result = await listQuery(
            query,
            USERS_LIST_SCHEMA,
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
            const err = new Error(result.error);
            err.status = result.status ?? 400;
            throw err;
        }

        return result;
    }
}

export default new AuthService();