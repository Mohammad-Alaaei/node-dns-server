'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface) {
    const transaction = await queryInterface.sequelize.transaction();

    try {
      const servers = await queryInterface.bulkInsert('dns_servers', [
        {
          ip: '78.157.42.100',
          type: 'CUSTOM',
          enabled: 1,
          priority: 10,
          average_latency: 0,
          successes: 0,
          failures: 0,
          timeouts: 0
        },
      ], {
        returning: true
      });

      await queryInterface.bulkInsert('dns_rules', [
        {
          server_id: servers,
          domain: '.*\\.googlevideo\\.com',
          is_regex: 1
        }, {
          server_id: servers,
          domain: '.*\\.ir$',
          is_regex: 1
        }
      ]);

      await transaction.commit();

    } catch (error) {
      await transaction.rollback();
      throw error;
    }
  },

  async down(queryInterface) {
    await queryInterface.bulkDelete('dns_rules', [
      {
        domain: '.*\\.googlevideo\\.com'
      },
      {
        domain: '.*\\.ir$'
      }
    ]);
    await queryInterface.bulkDelete('dns_servers', {
      ip: ['78.157.42.100'],
      type: 'CUSTOM'
    });
  }
};