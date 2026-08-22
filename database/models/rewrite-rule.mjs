import { sequelize, DataTypes } from '../connection.mjs';

export const RewriteRule = sequelize.define('rewrite_rules', {
    id: {
        type: DataTypes.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
    },
    name: {
        type: DataTypes.STRING(128),
        allowNull: true
    },
    pattern: {
        type: DataTypes.STRING(512),
        allowNull: false,
        unique: true
    },
    action: {
        type: DataTypes.STRING(64),
        allowNull: false
    },
    params: {
        type: DataTypes.JSON,
        allowNull: false
    },
    enabled: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: true
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
    tableName: 'rewrite_rules',
    indexes: [
        { fields: ['enabled'], name: 'idx_rewrite_rules_enabled' },
        { fields: ['action'], name: 'idx_rewrite_rules_action' }
    ]
});
