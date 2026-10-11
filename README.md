# Eskaen Vault

**Secure document management platform** for Eskaen Technologies. Token-based authentication with role-based access control, expiring API keys, and a minimalist modern interface.

Built for the 15-document startup governance framework at `vault.eskaen.com`.

---

## Features

- **Token-Based Auth** — API keys with configurable expiry and role-based permissions
- **Role Hierarchy** — Super Admin, Admin, Editor, Viewer with granular access
- **Document Management** — Upload, organize by category, version tracking
- **Expiring Keys** — Tokens automatically expire; extend or revoke as needed
- **Activity Logging** — Full audit trail of all vault actions
- **Beautiful UI** — Minimalist dark theme, responsive design
- **Docker Ready** — Deploy anywhere with Docker Compose

## Role Permissions

| Role        | View | Upload | Edit | Delete | Manage Tokens | View Activity |
| ----------- | ---- | ------ | ---- | ------ | ------------- | ------------- |
| Super Admin | ✓   | ✓     | ✓   | ✓     | ✓            | ✓            |
| Admin       | ✓   | ✓     | ✓   | ✓     | ✓            | ✓            |
| Editor      | ✓   | ✓     | ✓   | ✗     | ✗            | ✗            |
| Viewer      | ✓   | ✗     | ✗   | ✗     | ✗            | ✗            |

## Quick Start

### Using Docker (Recommended)

```bash
# Clone and run
docker compose up -d

# Seed the database (first run only)
docker exec eskaen-vault node seed.js
```

### Manual Setup

```bash
# Install dependencies
cd backend && npm install

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Seed the database (creates super admin key)
node seed.js

# Start the server
node index.js
```

### Environment Variables

| Variable               | Description                       | Default         |
| ---------------------- | --------------------------------- | --------------- |
| `PORT`               | API server port                   | `3001`        |
| `JWT_SECRET`         | Secret for JWT signing            | *required*    |
| `SUPER_ADMIN_KEY`    | Override auto-generated super key | *auto*        |
| `TOKEN_EXPIRY_HOURS` | Default token lifetime            | `24`          |
| `NODE_ENV`           | Environment mode                  | `development` |

## API Endpoints

### Authentication

- `POST /api/auth/login` — Authenticate with API key, receive JWT
- `GET /api/auth/verify` — Verify current token validity

### Documents

- `GET /api/documents` — List documents (filter by category, search)
- `GET /api/documents/:id` — Get document details
- `GET /api/documents/:id/download` — Download document file
- `POST /api/documents` — Upload new document (Editor+)
- `PATCH /api/documents/:id` — Update document metadata (Editor+)
- `DELETE /api/documents/:id` — Archive document (Admin+)

### Tokens

- `GET /api/tokens` — List all tokens (Admin+)
- `POST /api/tokens` — Create new token (Admin+)
- `DELETE /api/tokens/:id` — Revoke token (Admin+)
- `PATCH /api/tokens/:id/extend` — Extend token expiry (Admin+)

### Categories

- `GET /api/categories` — List all categories

### System

- `GET /api/stats` — Dashboard statistics
- `GET /api/activity` — Activity log (Admin+)

## Deployment

### Cloudflare (vault.eskaen.com)

1. Deploy the Docker container to your server
2. Set up Cloudflare DNS: `vault.eskaen.com` → your server IP
3. Configure Cloudflare SSL/TLS to Full
4. Use the provided `nginx.conf` with Cloudflare's origin certificates
5. Add a Cloudflare Page Rule or Worker for API routing if needed

### Nginx Configuration

An `nginx.conf` is provided for reverse proxy setup. Configure it for `vault.eskaen.com` and point the root to the frontend directory.

## License

Proprietary — Eskaen Technologies
