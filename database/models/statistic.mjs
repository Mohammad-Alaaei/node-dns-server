import { sequelize, DataTypes } from '../connection.mjs';

export const Statistic = sequelize.define('statistics', {
    key: {
        type: DataTypes.STRING(128),
        primaryKey: true
    },
    value: {
        type: DataTypes.TEXT,
        allowNull: true
    }
}, {
    tableName: 'statistics'
});