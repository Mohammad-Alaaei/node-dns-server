'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('dns_rules', {
      id: {
        type: Sequelize.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
      },
      server_id: {
        type: Sequelize.INTEGER.UNSIGNED,
        allowNull: false,
        references: {
          model: 'dns_servers',
          key: 'id'
        },
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE'
      },
      domain: {
        type: Sequelize.STRING(255),
        allowNull: false
      },
      is_regex: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: false
      }
    });

    await queryInterface.addIndex('dns_rules', ['server_id'], {
      name: 'idx_dns_rules_server'
    });
    await queryInterface.addIndex('dns_rules', ['domain'], {
      name: 'idx_dns_rules_domain'
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('dns_rules');
  }
};