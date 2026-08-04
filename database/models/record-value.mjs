import { sequelize, DataTypes } from '../connection.mjs';

export const RecordValue = sequelize.define('record_values', {
    id: {
        type: DataTypes.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
    },
    record_id: {
        type: DataTypes.INTEGER.UNSIGNED,
        allowNull: false
    },
    dns_server_id: {
        type: DataTypes.INTEGER.UNSIGNED,
        allowNull: true
    },
    type: {
        type: DataTypes.STRING(16),
        allowNull: false
    },
    status: {
        type: DataTypes.STRING(32),
        allowNull: false
    },
    value: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    ttl: {
        type: DataTypes.INTEGER,
        allowNull: true
    },
    selected: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false
    },
    is_stale: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false
    },
    last_success_at: {
        type: DataTypes.BIGINT,
        allowNull: true
    },
    expires_at: {
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
    tableName: 'record_values',
    indexes: [
        { fields: ['record_id'] },
        { fields: ['dns_server_id'] },
        {
            unique: true,
            fields: ['record_id', 'dns_server_id', 'type'],
            name: 'idx_record_values_lookup'
        }
    ]
});