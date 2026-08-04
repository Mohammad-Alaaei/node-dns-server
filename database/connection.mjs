import { Sequelize, DataTypes } from 'sequelize';
import { config } from '../config/config.mjs';

const { db } = config;

const sequelize = new Sequelize(db.name, db.user, db.password, {
    host: db.host,
    port: db.port,
    dialect: 'mysql',
    logging: db.logging ? console.log : false,
    pool: {
        max: db.pool.max,
        min: db.pool.min,
        acquire: db.pool.acquire,
        idle: db.pool.idle
    },
    define: {
        timestamps: false,
        underscored: true
    }
});

async function authenticate() {
    await sequelize.authenticate();
}

async function close() {
    await sequelize.close();
}

export {
    sequelize,
    DataTypes,
    Sequelize,
    authenticate,
    close
};

export default sequelize;