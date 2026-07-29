import sqlite3 from 'sqlite3';

sqlite3.verbose();

const db = new sqlite3.Database('./data/dns.db', err => {
    if (err) {
        throw err;
    }
});

db.serialize(() => {
    db.run('PRAGMA journal_mode = WAL');
    db.run('PRAGMA synchronous = NORMAL');
    db.run('PRAGMA foreign_keys = ON');
    db.run('PRAGMA cache_size = -50000');
});

export function run(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) {
                reject(err);
                return;
            }

            resolve({
                lastID: this.lastID,
                changes: this.changes
            });
        });
    });
}

export function get(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) {
                reject(err);
                return;
            }

            resolve(row);
        });
    });
}

export function all(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) {
                reject(err);
                return;
            }

            resolve(rows);
        });
    });
}

export function exec(sql) {
    return new Promise((resolve, reject) => {
        db.exec(sql, err => {
            if (err) {
                reject(err);
                return;
            }

            resolve();
        });
    });
}

export async function transaction(callback, root = true) {

    if (root) {
        await run('BEGIN TRANSACTION');
    }

    try {
        await callback();

        if (root) {
            await run('COMMIT');
        }

    } catch (err) {
        if (root) {
            await run('ROLLBACK');
        }

        throw err;
    }
}

export function close() {
    return new Promise((resolve, reject) => {
        db.close(err => {
            if (err) {
                reject(err);
                return;
            }

            resolve();
        });
    });
}

export default db;