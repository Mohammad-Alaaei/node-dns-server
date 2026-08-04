import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import mysql from 'mysql2/promise';
import { config } from '../config/config.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

const MYSQL_ROOT_USER = process.env.MYSQL_ROOT_USER;
const MYSQL_ROOT_PASSWORD = process.env.MYSQL_ROOT_PASSWORD;

const {
    host: DB_HOST,
    port: DB_PORT,
    name: DB_NAME,
    user: DB_USER,
    password: DB_PASSWORD
} = config.db;

if (!MYSQL_ROOT_USER || !MYSQL_ROOT_PASSWORD) {
    console.error('Missing MYSQL_ROOT_USER or MYSQL_ROOT_PASSWORD');
    process.exit(1);
}

const templatePath = path.join(root, 'data', 'create-db.sql');
let sql = fs.readFileSync(templatePath, 'utf8');

sql = sql
    .replaceAll('${DB_NAME}', DB_NAME.replace(/`/g, ''))
    .replaceAll('${DB_USER}', DB_USER.replace(/'/g, "\\'"))
    .replaceAll('${DB_PASSWORD}', DB_PASSWORD.replace(/'/g, "\\'"));

const connection = await mysql.createConnection({
    host: DB_HOST,
    port: Number(DB_PORT),
    user: MYSQL_ROOT_USER,
    password: MYSQL_ROOT_PASSWORD,
    multipleStatements: true
});

try {
    console.log(`Connecting as ${MYSQL_ROOT_USER}@${DB_HOST}:${DB_PORT} ...`);
    await connection.query(sql);
    console.log(`Database "${DB_NAME}" and user "${DB_USER}" are ready.`);
} catch (err) {
    console.error('Failed to create database:', err.message);
    process.exitCode = 1;
} finally {
    await connection.end();
}