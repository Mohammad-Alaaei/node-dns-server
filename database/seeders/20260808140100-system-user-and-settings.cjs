'use strict';

/**
 * System user (id = 0) + default system settings JSON.
 * Must run after users table exists. Not a login account.
 */

const SYSTEM_USER_ID = 0;

// Unusable bcrypt-shaped placeholder (login for this user is not supported)
const SYSTEM_PASSWORD_HASH =
  '$2a$10$systemuserplaceholderhashnotforloginxxxxxxxxxxxx';

function parseIpList(value) {
  return (value ?? '')
    .split(/[\s,]+/)
    .map(s => s.trim())
    .filter(Boolean);
}

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface) {
    const now = Date.now();

    // MySQL treats explicit 0 as "next AI" unless NO_AUTO_VALUE_ON_ZERO is set
    await queryInterface.sequelize.query(
      "SET SESSION sql_mode = CONCAT(@@sql_mode, ',NO_AUTO_VALUE_ON_ZERO')"
    );

    await queryInterface.bulkInsert('users', [
      {
        id: SYSTEM_USER_ID,
        username: '__system__',
        password_hash: SYSTEM_PASSWORD_HASH,
        role: 'system',
        created_at: now,
        updated_at: now
      }
    ]);

    const systemSettings = {
      cache: {
        level: process.env.CACHE_LEVEL ?? 'CUSTOM_ONLY',
        expireTime: Number(process.env.CACHE_EXPIRE_TIME ?? 60),
        flushInterval: Number(process.env.FLUSH_INTERVAL_MS ?? 60000),
        filterIps: parseIpList(process.env.FILTER_IPS)
      },
      ignoreIps: parseIpList(process.env.IGNORE_IPS),
      dns: {
        ttl: Number(process.env.DNS_TTL ?? 60),
        timeout: Number(process.env.DNS_TIMEOUT ?? 8000)
      },
      server: {
        ptrHostname: process.env.PTR_HOSTNAME ?? 'localhost.com',
        debugPrefix: process.env.DEBUG_PREFIX ?? '_.'
      }
    };

    await queryInterface.bulkInsert('settings', [
      {
        user_id: SYSTEM_USER_ID,
        value: JSON.stringify(systemSettings),
        updated_at: now
      }
    ]);
  },

  async down(queryInterface) {
    await queryInterface.bulkDelete('settings', { user_id: SYSTEM_USER_ID });
    await queryInterface.bulkDelete('users', { id: SYSTEM_USER_ID });
  }
};
