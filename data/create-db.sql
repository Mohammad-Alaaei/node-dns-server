-- Bootstrap SQL for this app's database on a shared MySQL server.
-- Do NOT hardcode names/passwords here.
-- Run via: npm run db:create
-- which connects as MYSQL_ROOT_USER / MYSQL_ROOT_PASSWORD and substitutes:
--   DB_NAME, DB_USER, DB_PASSWORD

CREATE DATABASE IF NOT EXISTS `${DB_NAME}`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASSWORD}';
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';

GRANT ALL PRIVILEGES ON `${DB_NAME}`.* TO '${DB_USER}'@'%';
GRANT ALL PRIVILEGES ON `${DB_NAME}`.* TO '${DB_USER}'@'localhost';

FLUSH PRIVILEGES;