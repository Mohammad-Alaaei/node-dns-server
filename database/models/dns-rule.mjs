import { sequelize, DataTypes } from '../connection.mjs';

export const DnsRule = sequelize.define('dns_rules', {
    id: {
        type: DataTypes.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
    },
    server_id: {
        type: DataTypes.INTEGER.UNSIGNED,
        allowNull: false
    },
    domain: {
        type: DataTypes.STRING(255),
        allowNull: false
    },
    is_regex: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false
    }
}, {
    tableName: 'dns_rules',
    indexes: [
        { fields: ['server_id'] },
        { fields: ['domain'] }
    ]
});