import { sequelize, DataTypes } from '../connection.mjs';

export const DnsServer = sequelize.define('dns_servers', {
    id: {
        type: DataTypes.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
    },
    ip: {
        type: DataTypes.STRING(45),
        allowNull: false,
        unique: true
    },
    type: {
        type: DataTypes.STRING(32),
        allowNull: false
    },
    enabled: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: true
    },
    priority: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 0
    },
    average_latency: {
        type: DataTypes.FLOAT,
        allowNull: false,
        defaultValue: 0
    },
    successes: {
        type: DataTypes.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 0
    },
    failures: {
        type: DataTypes.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 0
    },
    timeouts: {
        type: DataTypes.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 0
    }
}, {
    tableName: 'dns_servers'
});