import { sequelize, DataTypes } from '../connection.mjs';

export const Setting = sequelize.define('settings', {
    key: {
        type: DataTypes.STRING(128),
        primaryKey: true
    },
    value: {
        type: DataTypes.TEXT,
        allowNull: true
    }
}, {
    tableName: 'settings'
});