'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('external_resolvers', {
      id: {
        type: Sequelize.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
      },
      provider: {
        type: Sequelize.STRING(64),
        allowNull: false
      },
      name: {
        type: Sequelize.STRING(128),
        allowNull: false
      },
      mode: {
        type: Sequelize.STRING(32),
        allowNull: false,
        defaultValue: 'manual_only'
      },
      enabled: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: true
      },
      config: {
        type: Sequelize.JSON,
        allowNull: false
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

    await queryInterface.addIndex('external_resolvers', ['provider'], {
      name: 'idx_external_resolvers_provider'
    });
    await queryInterface.addIndex('external_resolvers', ['enabled'], {
      name: 'idx_external_resolvers_enabled'
    });
    await queryInterface.addIndex('external_resolvers', ['mode'], {
      name: 'idx_external_resolvers_mode'
    });

    await queryInterface.createTable('external_resolver_keys', {
      id: {
        type: Sequelize.INTEGER.UNSIGNED,
        autoIncrement: true,
        primaryKey: true
      },
      resolver_id: {
        type: Sequelize.INTEGER.UNSIGNED,
        allowNull: false,
        references: {
          model: 'external_resolvers',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
      },
      api_key: {
        type: Sequelize.STRING(512),
        allowNull: false
      },
      label: {
        type: Sequelize.STRING(128),
        allowNull: true
      },
      priority: {
        type: Sequelize.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 0
      },
      enabled: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: true
      },
      period_limit: {
        type: Sequelize.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 0
      },
      used_count: {
        type: Sequelize.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 0
      },
      period_start: {
        type: Sequelize.BIGINT,
        allowNull: false
      },
      period_ms: {
        type: Sequelize.INTEGER.UNSIGNED,
        allowNull: false,
        defaultValue: 86400000
      },
      last_error: {
        type: Sequelize.STRING(512),
        allowNull: true
      },
      last_used_at: {
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

    await queryInterface.addIndex('external_resolver_keys', ['resolver_id'], {
      name: 'idx_external_resolver_keys_resolver_id'
    });
    await queryInterface.addIndex('external_resolver_keys', ['resolver_id', 'priority'], {
      name: 'idx_external_resolver_keys_queue'
    });
    await queryInterface.addIndex('external_resolver_keys', ['enabled'], {
      name: 'idx_external_resolver_keys_enabled'
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('external_resolver_keys');
    await queryInterface.dropTable('external_resolvers');
  }
};
