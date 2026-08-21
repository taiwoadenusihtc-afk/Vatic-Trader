-- VaticTrader backend schema
-- Mirrors the existing window.storage key-value shape used throughout the
-- frontend, so the app's data model doesn't need to be redesigned to gain
-- real persistence — just the transport underneath it changes.

CREATE TABLE IF NOT EXISTS users (
  username      TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,
  username    TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Shared key-value store: readable/writable by any authenticated user.
-- Used for: user:<username> profile blobs, community-index, follows-index,
-- waitlist-index (matching the exact keys the frontend already uses).
CREATE TABLE IF NOT EXISTS kv_shared (
  key         TEXT PRIMARY KEY,
  value       TEXT NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Personal key-value store: scoped to the owning user only (e.g. "session").
CREATE TABLE IF NOT EXISTS kv_personal (
  username    TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  key         TEXT NOT NULL,
  value       TEXT NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (username, key)
);

CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);

-- Real broker API credentials (currently: Alpaca paper trading only).
-- api_secret is stored encrypted (AES-256-GCM) — see encryptSecret() in
-- server.js — never returned to the client after the initial connect.
CREATE TABLE IF NOT EXISTS broker_credentials (
  username        TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  broker          TEXT NOT NULL DEFAULT 'alpaca',
  api_key_id      TEXT NOT NULL,
  api_secret_enc  TEXT NOT NULL,
  base_url        TEXT NOT NULL DEFAULT 'https://paper-api.alpaca.markets',
  connected_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (username, broker)
);
