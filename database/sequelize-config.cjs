'use strict';

/**
 * Sequelize CLI config.
 * Loads the single app config (config.mjs) via dynamic import — no second .env reader.
 */
module.exports = async () => {
  const { config } = await import('../config/config.mjs');

  const shared = {
    username: config.db.user,
    password: config.db.password,
    database: config.db.name,
    host: config.db.host,
    port: config.db.port,
    dialect: 'mysql',
    logging: config.db.logging ? console.log : false,
    pool: {
      max: config.db.pool.max,
      min: config.db.pool.min,
      acquire: config.db.pool.acquire,
      idle: config.db.pool.idle
    },
    define: {
      timestamps: false,
      underscored: true
    }
  };

  return {
    development: shared,
    test: shared,
    production: shared
  };
};