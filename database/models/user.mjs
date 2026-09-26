import { sequelize, DataTypes } from '../connection.mjs';

/**
 * Roles:
 *   system     — internal row (id=0), not for login
 *   superadmin — full control
 *   admin      — manage users (limited) + app config
 *   viewer     — read-only
 *
 * Soft delete: deleted_at set → excluded from auth and default lists.
 * enabled=false → cannot login (admin can re-enable).
 */
export const User = sequelize.define('users', {
    id: {
        type: DataTypes.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
    },
    username: {
        type: DataTypes.STRING(64),
        allowNull: false,
        unique: true
    },
    password_hash: {
        type: DataTypes.STRING(255),
        allowNull: false
    },
    role: {
        type: DataTypes.STRING(32),
        allowNull: false,
        defaultValue: 'viewer'
    },
    enabled: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: true
    },
    deleted_at: {
        type: DataTypes.BIGINT,
        allowNull: true,
        defaultValue: null
    },
    created_at: {
        type: DataTypes.BIGINT,
        allowNull: false
    },
    updated_at: {
        type: DataTypes.BIGINT,
        allowNull: false
    }
}, {
    tableName: 'users'
});
