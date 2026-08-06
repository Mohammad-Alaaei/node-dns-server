import { sequelize, DataTypes } from '../connection.mjs';

/**
 * Opaque refresh tokens (not JWTs).
 * Only the SHA-256 hash is stored so a DB leak does not yield usable tokens.
 */
export const RefreshToken = sequelize.define('refresh_tokens', {
    id: {
        type: DataTypes.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
    },
    user_id: {
        type: DataTypes.INTEGER.UNSIGNED,
        allowNull: false
    },
    token_hash: {
        type: DataTypes.STRING(64),
        allowNull: false,
        unique: true
    },
    expires_at: {
        type: DataTypes.BIGINT,
        allowNull: false
    },
    revoked_at: {
        type: DataTypes.BIGINT,
        allowNull: true
    },
    created_at: {
        type: DataTypes.BIGINT,
        allowNull: false
    }
}, {
    tableName: 'refresh_tokens',
    indexes: [
        { fields: ['user_id'], name: 'idx_refresh_tokens_user_id' },
        { fields: ['expires_at'], name: 'idx_refresh_tokens_expires_at' }
    ]
});
