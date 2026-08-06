import jwt from 'jsonwebtoken';
import { createHash, randomBytes } from 'node:crypto';
import { config } from '../../../config/config.mjs';
import { RefreshToken, User } from '../../../database/models/index.mjs';

/** Parse "15m" / "7d" / "3600" into milliseconds. */
function durationToMs(value) {
    if (typeof value === 'number' && Number.isFinite(value)) {
        return value;
    }

    const s = String(value).trim();
    const m = /^(\d+)(ms|s|m|h|d)?$/i.exec(s);
    if (!m) {
        return 15 * 60 * 1000;
    }

    const n = Number(m[1]);
    const unit = (m[2] || 's').toLowerCase();

    switch (unit) {
        case 'ms': return n;
        case 's': return n * 1000;
        case 'm': return n * 60 * 1000;
        case 'h': return n * 60 * 60 * 1000;
        case 'd': return n * 24 * 60 * 60 * 1000;
        default: return n * 1000;
    }
}

function hashToken(raw) {
    return createHash('sha256').update(raw).digest('hex');
}

/**
 * Short-lived access JWT (Authorization: Bearer …).
 */
export function signAccessToken(user) {
    const payload = {
        sub: user.id,
        username: user.username,
        role: user.role,
        typ: 'access'
    };

    return jwt.sign(payload, config.api.jwtSecret, {
        expiresIn: config.api.jwtExpiresIn
    });
}

/** @deprecated use signAccessToken */
export function signToken(user) {
    return signAccessToken(user);
}

export function verifyAccessToken(token) {
    const payload = jwt.verify(token, config.api.jwtSecret);
    if (payload.typ && payload.typ !== 'access') {
        throw new Error('Not an access token');
    }
    return payload;
}

/** @deprecated use verifyAccessToken */
export function verifyToken(token) {
    return verifyAccessToken(token);
}

/**
 * Create an opaque refresh token, store its hash in DB, return the raw token once.
 */
export async function issueRefreshToken(userId) {
    const raw = randomBytes(48).toString('base64url');
    const token_hash = hashToken(raw);
    const now = Date.now();
    const expires_at = now + durationToMs(config.api.refreshExpiresIn);

    await RefreshToken.create({
        user_id: userId,
        token_hash,
        expires_at,
        revoked_at: null,
        created_at: now
    });

    return {
        refreshToken: raw,
        refreshExpiresAt: expires_at,
        refreshExpiresIn: config.api.refreshExpiresIn
    };
}

/**
 * Validate refresh token → user row. Returns null if invalid/expired/revoked.
 */
export async function findUserByRefreshToken(raw) {
    if (!raw || typeof raw !== 'string') {
        return null;
    }

    const token_hash = hashToken(raw);
    const row = await RefreshToken.findOne({ where: { token_hash } });

    if (!row) {
        return null;
    }

    if (row.revoked_at != null) {
        return null;
    }

    if (row.expires_at <= Date.now()) {
        return null;
    }

    const user = await User.findByPk(row.user_id);
    if (!user) {
        return null;
    }

    return { user, refreshRow: row };
}

/**
 * Revoke one refresh token (logout). Idempotent.
 */
export async function revokeRefreshToken(raw) {
    if (!raw) return false;

    const token_hash = hashToken(raw);
    const [n] = await RefreshToken.update(
        { revoked_at: Date.now() },
        {
            where: {
                token_hash,
                revoked_at: null
            }
        }
    );
    return n > 0;
}

/**
 * Rotate: revoke old refresh, issue a new one (recommended on every refresh).
 */
export async function rotateRefreshToken(raw) {
    const found = await findUserByRefreshToken(raw);
    if (!found) {
        return null;
    }

    await revokeRefreshToken(raw);
    const issued = await issueRefreshToken(found.user.id);

    return {
        user: found.user,
        ...issued
    };
}

export function accessTokenMeta() {
    return {
        expiresIn: config.api.jwtExpiresIn,
        expiresInMs: durationToMs(config.api.jwtExpiresIn)
    };
}
