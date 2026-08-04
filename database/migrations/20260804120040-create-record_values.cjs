'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {

    await queryInterface.createTable('record_values', {
      id: {
        type: Sequelize.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
      },
      record_id: {
        type: Sequelize.INTEGER.UNSIGNED,
        allowNull: false,
        references: {
          model: 'records',
          key: 'id'
        },
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE'
      },
      dns_server_id: {
        type: Sequelize.INTEGER.UNSIGNED,
        allowNull: true,
        references: {
          model: 'dns_servers',
          key: 'id'
        },
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE'
      },
      type: {
        type: Sequelize.STRING(16),
        allowNull: false
      },
      status: {
        type: Sequelize.STRING(32),
        allowNull: false
      },
      value: {
        type: Sequelize.TEXT,
        allowNull: true
      },
      ttl: {
        type: Sequelize.INTEGER,
        allowNull: true
      },
      selected: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: false
      },
      is_stale: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: false
      },
      last_success_at: {
        type: Sequelize.BIGINT,
        allowNull: true
      },
      expires_at: {
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

    await queryInterface.addIndex('record_values', ['record_id'], {
      name: 'idx_record_values_record'
    });
    await queryInterface.addIndex('record_values', ['dns_server_id'], {
      name: 'idx_record_values_server'
    });
    await queryInterface.addIndex(
      'record_values',
      ['record_id', 'dns_server_id', 'type'],
      {
        unique: true,
        name: 'idx_record_values_lookup'
      }
    );
  },

  async down(queryInterface) {
    await queryInterface.dropTable('record_values');
  }
};