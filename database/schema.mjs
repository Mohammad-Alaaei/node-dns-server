import { exec } from './sqlite.mjs';

export async function createSchema() {

    await exec(`
        CREATE TABLE IF NOT EXISTS dns_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            priority INTEGER NOT NULL DEFAULT 0,
            average_latency REAL NOT NULL DEFAULT 0,
            successes INTEGER NOT NULL DEFAULT 0,
            failures INTEGER NOT NULL DEFAULT 0,
            timeouts INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS dns_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            is_regex INTEGER NOT NULL DEFAULT 0,

            FOREIGN KEY(server_id)
                REFERENCES dns_servers(id)
                ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_dns_rules_server
            ON dns_rules(server_id);

        CREATE INDEX IF NOT EXISTS idx_dns_rules_domain
            ON dns_rules(domain);

        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            domain TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            is_regex INTEGER NOT NULL DEFAULT 0,
            source TEXT NOT NULL,
            hits INTEGER NOT NULL DEFAULT 0,
            last_hit INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS record_values (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            record_id INTEGER NOT NULL,
            dns_server_id INTEGER,
            type TEXT NOT NULL,
            status TEXT NOT NULL,
            value TEXT,
            ttl INTEGER,
            selected INTEGER NOT NULL DEFAULT 0,
            is_stale INTEGER NOT NULL DEFAULT 0,
            last_success_at INTEGER,
            expires_at INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,

            FOREIGN KEY(record_id)
                REFERENCES records(id)
                ON DELETE CASCADE,

            FOREIGN KEY(dns_server_id)
                REFERENCES dns_servers(id)
                ON DELETE CASCADE,

            UNIQUE(record_id, dns_server_id, type)
        );

        CREATE INDEX IF NOT EXISTS idx_record_values_record
            ON record_values(record_id);

        CREATE INDEX IF NOT EXISTS idx_record_values_server
            ON record_values(dns_server_id);

        CREATE INDEX IF NOT EXISTS idx_record_values_lookup
            ON record_values(record_id, dns_server_id, type);

        CREATE UNIQUE INDEX IF NOT EXISTS idx_records_domain_source
            ON records(domain, source);

        CREATE INDEX IF NOT EXISTS idx_records_domain
            ON records(domain);

        CREATE INDEX IF NOT EXISTS idx_records_source
            ON records(source);

        CREATE TABLE IF NOT EXISTS statistics (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    `);
}