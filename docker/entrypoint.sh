#!/bin/sh
set -e

echo "==> Waiting for MySQL at ${DB_HOST}:${DB_PORT}..."

# Simple wait loop (no extra packages needed on alpine)
until node -e "
  const net = require('net');
  const s = net.connect({ host: process.env.DB_HOST || 'db', port: Number(process.env.DB_PORT || 3306) }, () => { s.end(); process.exit(0); });
  s.on('error', () => process.exit(1));
" 2>/dev/null; do
  echo "    MySQL is unavailable - sleeping"
  sleep 2
done

echo "==> MySQL is up"

# Always run migrations (idempotent)
echo "==> Running migrations..."
npx sequelize-cli db:migrate --env production

# Seeds only once (marker file lives on a volume)
SEED_MARKER="/app/data/.seeded"
if [ ! -f "$SEED_MARKER" ]; then
  echo "==> First run – executing seeders..."
  npx sequelize-cli db:seed:all --env production || true
  touch "$SEED_MARKER"
  echo "==> Seed marker created"
else
  echo "==> Seed marker found – skipping seeders"
fi

echo "==> Starting DNS server..."
exec node main.mjs
