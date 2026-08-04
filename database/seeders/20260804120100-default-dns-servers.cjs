'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface) {
    await queryInterface.bulkInsert('dns_servers', [
      {
        ip: '8.8.8.8',
        type: 'DEFAULT',
        enabled: 1,
        priority: 10,
        average_latency: 0,
        successes: 0,
        failures: 0,
        timeouts: 0
      }
    ]);
  },

  async down(queryInterface) {
    await queryInterface.bulkDelete('dns_servers', {
      ip: ['8.8.8.8'],
      type: 'DEFAULT'
    });
  }
};