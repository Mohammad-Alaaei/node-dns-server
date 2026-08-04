'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {

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

  },

  async down(queryInterface) {
    await queryInterface.dropTable('settings');
  }
};