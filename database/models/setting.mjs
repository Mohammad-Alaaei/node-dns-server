import { sequelize, DataTypes } from '../connection.mjs';

/**
 * One JSON document per user_id.
 * user_id = 0 → system-wide settings (not a real users row).
 */
export const Setting = sequelize.define('settings', {
    user_id: {
        type: DataTypes.INTEGER.UNSIGNED,
        primaryKey: true,
        allowNull: false
    },
    value: {
        type: DataTypes.TEXT,
        allowNull: false,
        defaultValue: '{}'
    },
    updated_at: {
        type: DataTypes.BIGINT,
        allowNull: false
    }
}, {
    tableName: 'settings'
});
