# Classified Document Integrity and Clearance Verification

Secure document handling with encrypted storage, integrity verification, clearance-based access, and a hash-chained audit ledger.

## What this does

- Encrypts and stores uploaded documents off-chain on disk.
- Registers SHA-256 hashes to detect tampering.
- Enforces clearance levels for access and downloads.
- Records every action in an immutable, hash-chained audit ledger.
- Offers optional AI-assisted access and threat summaries via Gemini.

## Tech stack

- Node.js 18
- Express 5
- MySQL 8 (or compatible)
- JWT authentication
- AES-256-GCM encryption for documents

## Project layout

```
Documentation/
Screenshots/
Web_Backend/
  server.js
  config.js
  schema.sql
  routes/
  services/
  middleware/
  secure_storage/
```

## Setup

### Prerequisites

- Node.js 18.x
- MySQL 8.x

### 1) Install dependencies

```
cd Web_Backend
npm install
```

### 2) Configure environment variables

Create a `.env` file in `Web_Backend/`:

```
PORT=3000
JWT_SECRET=your_access_token_secret
JWT_REFRESH_SECRET=your_refresh_token_secret
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d
ENCRYPTION_KEY=base64_or_64_hex_chars_key

DB_HOST=localhost
DB_PORT=3306
DB_NAME=cdi_platform
DB_USER=root
DB_PASSWORD=your_password

# Optional (enables AI responses)
GEMINI_API_KEY=your_gemini_key
GEMINI_MODEL=gemini-1.5-flash
```

Notes:
- `ENCRYPTION_KEY` must be 32 bytes. Use either 64 hex characters or base64-encoded 32 bytes.
- If `GEMINI_API_KEY` is not set, the app falls back to rule-based responses.

### 3) Initialize the database

Create the database and run the schema:

```
CREATE DATABASE cdi_platform;
USE cdi_platform;
SOURCE schema.sql;
```

### 4) Start the server

```
npm start
```

The server runs at `http://localhost:3000`.

## Default admin

On first start, a default admin is seeded if no admin exists:

- Username: `admin`
- Password: `admin12345678`
- Role: `TOP_SECRET` (clearance level 5)

Change this immediately in production.

## Core API endpoints

Auth:
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `POST /auth/users` (requires `TOP_SECRET`)

Documents:
- `POST /documents/upload` (multipart form field: `document`)
- `GET /documents`
- `GET /documents/:id`
- `POST /documents/:id/verify`
- `GET /documents/:id/download`

Access control:
- `POST /access/request`

Audit ledger:
- `GET /audit/ledger`
- `GET /audit/verify` (requires `TOP_SECRET`)

AI utilities:
- `POST /chat` (access questions and document metadata)
- `GET /threats/summary`

## Clearance levels

Roles map to numeric clearance levels:

- `UNCLASSIFIED` -> 1
- `RESTRICTED` -> 2
- `CONFIDENTIAL` -> 3
- `SECRET` -> 4
- `TOP_SECRET` -> 5

A user can access a document if `clearanceLevel >= required_clearance`.

## Security notes

- Documents are encrypted at rest in `Web_Backend/secure_storage/`.
- Hashes are recalculated on verification to detect tampering.
- Audit ledger entries are hash-chained to detect modification.

## Useful checks

- `GET /health` for a quick server health check.
- If uploads fail, verify `ENCRYPTION_KEY` and `ALLOWED_MIME_TYPES` in the environment.
