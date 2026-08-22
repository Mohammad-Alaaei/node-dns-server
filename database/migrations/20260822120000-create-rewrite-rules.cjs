'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('rewrite_rules', {
      id: {
        type: Sequelize.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
      },
      name: {
        type: Sequelize.STRING(128),
        allowNull: true
      },
      pattern: {
        type: Sequelize.STRING(512),
        allowNull: false,
        unique: true
      },
      action: {
        type: Sequelize.STRING(64),
        allowNull: false
      },
      params: {
        type: Sequelize.JSON,
        allowNull: false
      },
      enabled: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: true
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

    await queryInterface.addIndex('rewrite_rules', ['enabled'], {
      name: 'idx_rewrite_rules_enabled'
    });
    await queryInterface.addIndex('rewrite_rules', ['action'], {
      name: 'idx_rewrite_rules_action'
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('rewrite_rules');
  }
};
