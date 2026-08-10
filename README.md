```markdown
# node-dns-server

Custom DNS server written in Node.js.

It receives DNS requests and decides what to do with them:

1. Override domains with static IPs
2. Route specific domains to custom upstream DNS servers
3. Cache answers (with configurable levels: `ALL`, `CUSTOM_ONLY`, `FILTERED_ONLY`, `NONE`), track hits/latency, mark “filtered” answers, and persist everything in MySQL.

## Architecture notes

- Clean separation of concerns, graceful shutdown, latency tracking per upstream
- Regex + exact matching (longer regexes preferred)
- Debug mode via `_.` prefix
- TTL/expiry handling and “selected”/stale server logic
- Cache flush is periodic and merges answers
- HTTP API with JWT + refresh tokens and RSA-OAEP login encryption

## Requirements

- Node.js 18+ (22 recommended)
- MySQL 8
- npm

---

## Local development setup

### 1. Install dependencies

```bash
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
# edit DB_*, ADMIN_*, API_JWT_SECRET, etc.
```

### 3. Initialize the database

```bash
npm run db:create      # creates database + user (needs MYSQL_ROOT_* credentials)
npm run db:migrate
npm run db:seed
```

### 4. Run the server

```bash
node main.mjs
# or on Windows: run.bat
```

The DNS server listens on the configured `SERVER_IP`/`SERVER_PORT` (default `127.0.0.1:53`).  
The HTTP API listens on `API_HOST`/`API_PORT` (default `127.0.0.1:3000`).

---

## Docker setup

This repository ships a self-contained Docker setup that runs **MySQL + the DNS server + phpMyAdmin**.

### Files

```
docker/
  Dockerfile          # production image (node:22-alpine)
  entrypoint.sh       # wait-for-db → migrate → seed-once → start
docker-compose.yml    # backend + MySQL + phpMyAdmin
.dockerignore
```

### Quick start

```bash
# from the root of this repository
cp .env.example .env          # optional – edit secrets
docker compose up -d --build
```

**Published ports**

| Port   | Service     |
| ------ | ----------- |
| 53/udp | DNS         |
| 3000   | HTTP API    |
| 8080   | phpMyAdmin  |

**Volumes** (persist across rebuilds)

- `mysql_data` – database files
- `backend_logs` – application logs
- `backend_data` – seed marker (seeds run only once)

### Behaviour on start

1. Wait until MySQL is healthy
2. Run migrations (always)
3. Run seeders **only on first boot** (controlled by a marker file in the `backend_data` volume)
4. Start the DNS server + API

### Environment

All configuration is done via environment variables (see `.env.example`).  
Important Docker-related values already set in `docker-compose.yml`:

- `SERVER_IP=0.0.0.0` / `API_HOST=0.0.0.0` (listen on all interfaces inside the container)
- `DB_HOST=db`

### Rebuild / update

```bash
docker compose up -d --build
```

Logs and the seed marker survive the rebuild.  
To wipe everything (including the database):

```bash
docker compose down -v
```

---

## Configuration reference

See `.env.example` for the full list. Key groups:

| Group        | Purpose                             |
| ------------ | ----------------------------------- |
| `SERVER_*`   | DNS bind address / port             |
| `DB_*`       | MySQL connection                    |
| `API_*`      | HTTP API bind, JWT, CORS, RSA keys  |
| `ADMIN_*`    | Bootstrap superadmin (created once) |
| `CACHE_*`    | Cache level, TTL, flush interval    |
| `FILTER_IPS` | IPs that mark answers as FILTERED   |
| `LOG_*`      | Log directory and rotation          |

---

## License

GPL-3.0-only
ure the configured port is available and that the application has the required permissions to use it.
```