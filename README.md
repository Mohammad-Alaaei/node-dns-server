# What is this?

This is a simple DNS server made with Node.js.

It allows you to define custom IP addresses for domains, manage domains resolved through custom DNS servers, and cache DNS records.

The application uses MySQL as its database and Sequelize as its ORM.

## Quick Setup

### 1. Install Node.js

Install Node.js on your system.

### 2. Install dependencies

```cmd
npm install
```

### 3. Setup MySQL

Install and configure a MySQL server on your system.

Create a database user and make sure it has the required permissions to create and manage the application database.

### 4. Configure the environment

Update the `.env` file with your MySQL connection details.

Make sure the database host, port, username, password, and database settings are correct.

In particular, check the database username and password. If you are using the MySQL `root` user, make sure the `root` credentials in `.env` are correct.

### 5. Initialize the database

Run the following commands:

```cmd
npm run db:create
npm run db:migrate
npm run db:seed
```

These commands create the database, apply the database migrations, and add the default seed data.

### 6. Run the server

#### Windows

```cmd
node main.mjs
```

Or execute:

```cmd
run.bat
```

#### Linux

```cmd
node main.mjs
```

## Configuration

Application configuration is managed through environment variables.

Create or update your `.env` file according to the available configuration options in `.env.example`.

## Domain Management

DNS records are now managed through the database instead of the previous `domains.txt` and custom DNS server `.txt` files.

Records can be configured with their domain, IP addresses, source, and enabled state.

The application supports different record sources, including:

- `LOCAL` for manually configured records.
- `CACHE` for records resolved and stored by the DNS server.
- `FILTERED` for filtered records.

## DNS Resolution

When a requested domain does not have an applicable local record, the server can resolve it through the configured DNS servers.

Resolved records are stored in the database and can be served from the cache until they expire.

The server also supports CNAME records.

## Requirements

- Node.js
- MySQL
- npm

## Running the Server

The DNS server listens on the configured IP address and port.

Make sure the configured port is available and that the application has the required permissions to use it.
