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
            is_regex INTEGER NOT NULL DEFAULT 0,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            source TEXT NOT NULL,
            ttl INTEGER NOT NULL,
            expires_at INTEGER,
            hits INTEGER NOT NULL DEFAULT 0,
            last_hit INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

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