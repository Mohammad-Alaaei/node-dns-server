import { sequelize, DataTypes } from '../connection.mjs';

export const Record = sequelize.define('records', {
    id: {
        type: DataTypes.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
    },
    domain: {
        type: DataTypes.STRING(255),
        allowNull: false
    },
    enabled: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: true
    },
    is_regex: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false
    },
    source: {
        type: DataTypes.STRING(32),
        allowNull: false
    },
    hits: {
        type: DataTypes.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 0
    },
    last_hit: {
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
    tableName: 'records',
    indexes: [
        { unique: true, fields: ['domain', 'source'], name: 'idx_records_domain_source' },
        { fields: ['domain'] },
        { fields: ['source'] }
    ]
});