import { sequelize, DataTypes } from '../connection.mjs';

/**
 * Roles (expand later without schema change):
 *   superadmin — full control
 *   admin      — edit records / dns servers (future)
 *   viewer     — read-only (future)
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
