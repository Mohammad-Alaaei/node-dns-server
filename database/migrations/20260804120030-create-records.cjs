'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('records', {
      id: {
        type: Sequelize.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
      },
      domain: {
        type: Sequelize.STRING(255),
        allowNull: false,
        unique: true
      },
      enabled: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: true
      },
      is_regex: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: false
      },
      source: {
        type: Sequelize.STRING(32),
        allowNull: false
      },
      hits: {
        type: Sequelize.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 0
      },
      last_hit: {
        type: Sequelize.BIGINT,
        allowNull: true
      },
      created_at: {
        type: Sequelize.BIGINT,
        allowNull: false
      },
      updated_at: {
        type: Sequelize.BIGINT,
        allowNull: false
      }
    });

    await queryInterface.addIndex('records', ['source'], {
      name: 'idx_records_source'
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('records');
  }
};