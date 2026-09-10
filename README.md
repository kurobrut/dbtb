# Cubix Cloud — PostgreSQL Edition

This version replaces SQLite with Render PostgreSQL.

## Deploy with Render Blueprint

Push this folder to GitHub, then create a Render Blueprint from the repository.

The included `render.yaml` creates:
- `cubix-cloud` web service
- `cubix-cloud-db` PostgreSQL database
- `DATABASE_URL` wired automatically to the web service

Render supports wiring a database connection string directly into a service environment variable. Use the internal connection string for a Render-hosted web service in the same region.

## Existing Render web service

If you already have the web service:
1. Create a Render PostgreSQL database.
2. Open the database's Connect menu.
3. Copy the Internal Database URL.
4. Open your `cubix-cloud` web service → Environment.
5. Add/update `DATABASE_URL` with that value.
6. Deploy the updated code.

Do not put the database password directly into your source code.

## Important

This project no longer creates or reads `data.db`. Accounts, API tokens, and house records are stored in PostgreSQL.
