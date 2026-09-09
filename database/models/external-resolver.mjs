import { sequelize, DataTypes } from '../connection.mjs';

export const ExternalResolver = sequelize.define('external_resolvers', {
    id: {
        type: DataTypes.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
    },
    provider: {
        type: DataTypes.STRING(64),
        allowNull: false
    },
    name: {
        type: DataTypes.STRING(128),
        allowNull: false
    },
    mode: {
        type: DataTypes.STRING(32),
        allowNull: false,
        defaultValue: 'manual_only'
    },
    enabled: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: true
    },
    config: {
        type: DataTypes.JSON,
        allowNull: false,
        defaultValue: {}
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
    tableName: 'external_resolvers',
    indexes: [
        { fields: ['provider'], name: 'idx_external_resolvers_provider' },
        { fields: ['enabled'], name: 'idx_external_resolvers_enabled' },
        { fields: ['mode'], name: 'idx_external_resolvers_mode' }
    ]
});
