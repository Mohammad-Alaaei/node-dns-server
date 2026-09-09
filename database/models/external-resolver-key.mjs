import { sequelize, DataTypes } from '../connection.mjs';

export const ExternalResolverKey = sequelize.define('external_resolver_keys', {
    id: {
        type: DataTypes.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
    },
    resolver_id: {
        type: DataTypes.INTEGER.UNSIGNED,
        allowNull: false
    },
    api_key: {
        type: DataTypes.STRING(512),
        allowNull: false
    },
    label: {
        type: DataTypes.STRING(128),
        allowNull: true
    },
    priority: {
        type: DataTypes.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 0
    },
    enabled: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: true
    },
    period_limit: {
        type: DataTypes.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 0
    },
    used_count: {
        type: DataTypes.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 0
    },
    period_start: {
        type: DataTypes.BIGINT,
        allowNull: false
    },
    period_ms: {
        type: DataTypes.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 86400000
    },
    last_error: {
        type: DataTypes.STRING(512),
        allowNull: true
    },
    last_used_at: {
        type: DataTypes.BIGINT,
        allowNull: true
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
    tableName: 'external_resolver_keys',
    indexes: [
        { fields: ['resolver_id'], name: 'idx_external_resolver_keys_resolver_id' },
        { fields: ['resolver_id', 'priority'], name: 'idx_external_resolver_keys_queue' },
        { fields: ['enabled'], name: 'idx_external_resolver_keys_enabled' }
    ]
});
