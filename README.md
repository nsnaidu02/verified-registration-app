# Verified Registration App (Docker Compose)

A full-stack starter project implementing registration, email verification, Redis-backed pending registrations, PostgreSQL persistence, and login.

## Architecture

- **Frontend:** HTML, CSS, vanilla JavaScript served by Nginx (`http://localhost:8080`)
- **Backend:** Node.js + Express (`/api/*`, routed through Nginx)
- **Database:** PostgreSQL; verified users are stored in `users`
- **Redis:** pending registrations with automatic expiration
- **Email:** SMTP via Nodemailer

## Workflow

1. User submits name, email, and password on the frontend.
2. Backend validates input and hashes the password with bcrypt.
3. Backend stores the pending registration and a SHA-256 hash of the one-time verification token in Redis with a TTL (30 minutes by default).
4. Backend emails the raw verification link via SMTP.
5. The verification link sends the token to the backend. The backend scans pending-registration keys, compares token hashes, writes the verified account to PostgreSQL, and deletes the Redis entry.
6. Login checks the account and bcrypt password hash. Only users created by the verification flow exist in the users table.

Plaintext passwords are never stored in Redis or PostgreSQL. Verification tokens are random, one-time, and only their hashes are stored in Redis.

## Prerequisites

Install Docker Desktop (Windows/macOS) or Docker Engine + Docker Compose plugin (Linux).

## Setup

1. In this folder, copy `.env.example` to `.env`.
2. Edit `.env` and set SMTP credentials from your email provider. Use an app password where your provider requires one. Do not commit `.env`.
3. Change `POSTGRES_PASSWORD` to a long random value.
4. Build and start the services:

   ```bash
   docker compose up --build -d
   ```

5. Open `http://localhost:8080`.
6. Register using an inbox you can access. Open the verification email and click the link.
7. Log in using the same email and password.

Check services:

```bash
docker compose ps
docker compose logs -f backend
```

Health endpoint:

```bash
curl http://localhost:8080/api/health
```

It should return a JSON status showing PostgreSQL and Redis connected.

Stop services:

```bash
docker compose down
```

Stop and delete local database/Redis volumes (DESTRUCTIVE; deletes stored data):

```bash
docker compose down -v
```

## SMTP configuration

Email sending is intentionally not simulated. Registration returns an error if SMTP is not configured, so the app does not claim an email was sent when it was not.

Set these in `.env`:

- `SMTP_HOST`: your provider's SMTP hostname
- `SMTP_PORT`: commonly `587` for STARTTLS or `465` for implicit TLS
- `SMTP_SECURE`: `false` for port 587; `true` for port 465
- `SMTP_USER`, `SMTP_PASS`: SMTP credentials
- `MAIL_FROM`: a sender address permitted by your SMTP provider

If sending fails, inspect `docker compose logs -f backend`.

## Useful commands

```bash
docker compose ps
docker compose logs -f frontend backend db redis
docker compose restart backend
```

## Security notes before production

This is a working starter, not a complete production identity system.

- Put the site behind HTTPS and configure secure transport for SMTP.
- Add server-side sessions or short-lived access tokens plus refresh-token/session revocation. This demo's login endpoint verifies credentials and returns a user object, but does not maintain an authenticated session.
- Add CSRF protection if cookie-based sessions are introduced.
- Add stronger per-IP/per-email rate limiting and monitoring.
- Use a managed secret store for production secrets; never commit `.env`.
- For larger deployments, replace the Redis key scan with a token-hash-to-email index key, with the same TTL. That makes token lookup O(1) instead of scanning pending registrations.
- Add resend-verification and password-reset workflows with careful abuse prevention.
- Consider a database migration tool instead of relying on the first-start initialization script.
- Use generic login errors to reduce account enumeration. Registration currently gives a useful duplicate-email message for a learning/demo application.
