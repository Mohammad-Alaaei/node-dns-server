'use strict';

/**
 * v1 settings: one JSON blob per user_id.
 * user_id = 0 → system settings (users row seeded separately).
 * FK → users.id
 */

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.dropTable('settings');

    await queryInterface.createTable('settings', {
      user_id: {
        type: Sequelize.INTEGER.UNSIGNED,
        primaryKey: true,
        allowNull: false,
        references: {
          model: 'users',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE',
        comment: '0 = system; otherwise users.id'
      },
      value: {
        type: Sequelize.TEXT,
        allowNull: false,
        defaultValue: '{}'
      },
      updated_at: {
        type: Sequelize.BIGINT,
        allowNull: false
      }
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('settings');

    await queryInterface.createTable('settings', {
      key: {
        type: Sequelize.STRING(128),
        primaryKey: true
      },
      value: {
        type: Sequelize.TEXT,
        allowNull: true
      }
    });
  }
};
