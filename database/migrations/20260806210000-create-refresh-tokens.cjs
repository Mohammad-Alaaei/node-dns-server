'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('refresh_tokens', {
      id: {
        type: Sequelize.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
      },
      user_id: {
        type: Sequelize.INTEGER.UNSIGNED,
        allowNull: false,
        references: {
          model: 'users',
          key: 'id'
        },
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE'
      },
      token_hash: {
        type: Sequelize.STRING(64),
        allowNull: false,
        unique: true
      },
      expires_at: {
        type: Sequelize.BIGINT,
        allowNull: false
      },
      revoked_at: {
        type: Sequelize.BIGINT,
        allowNull: true
      },
      created_at: {
        type: Sequelize.BIGINT,
        allowNull: false
      }
    });

    await queryInterface.addIndex('refresh_tokens', ['user_id'], {
      name: 'idx_refresh_tokens_user_id'
    });
    await queryInterface.addIndex('refresh_tokens', ['expires_at'], {
      name: 'idx_refresh_tokens_expires_at'
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('refresh_tokens');
  }
};
