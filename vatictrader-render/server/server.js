const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL environment variable is not set.');
  process.exit(1);
}

const ENCRYPTION_KEY_RAW = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY_RAW) {
  console.error('FATAL: ENCRYPTION_KEY environment variable is not set (used to encrypt stored broker API secrets).');
  process.exit(1);
}
const ENC_KEY = crypto.createHash('sha256').update(ENCRYPTION_KEY_RAW).digest(); // always 32 bytes for AES-256

function encryptSecret(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}
function decryptSecret(encoded) {
  const buf = Buffer.from(encoded, 'base64');
  const iv = buf.subarray(0, 12);
  const authTag = buf.subarray(12, 28);
  const encrypted = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

const ALPACA_BASE_URL_DEFAULT = process.env.ALPACA_BASE_URL || 'https://paper-api.alpaca.markets';
async function alpacaRequest(baseUrl, apiKeyId, apiSecretKey, urlPath, options = {}) {
  return fetch(baseUrl + urlPath, {
    ...options,
    headers: Object.assign({
      'APCA-API-KEY-ID': apiKeyId,
      'APCA-API-SECRET-KEY': apiSecretKey,
      'Content-Type': 'application/json',
    }, options.headers || {}),
  });
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
});

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// ---------------------------------------------------------------- helpers
function newToken() {
  return crypto.randomBytes(32).toString('hex');
}
async function getUserFromToken(token) {
  if (!token) return null;
  const r = await pool.query('SELECT username FROM sessions WHERE token = $1', [token]);
  return r.rows.length ? r.rows[0].username : null;
}
function getToken(req) {
  const h = req.headers['authorization'] || '';
  if (h.startsWith('Bearer ')) return h.slice(7);
  return null;
}
async function requireAuth(req, res, next) {
  const token = getToken(req);
  const username = await getUserFromToken(token);
  if (!username) return res.status(401).json({ error: 'not authenticated' });
  req.username = username;
  next();
}
const USERNAME_RE = /^[a-z0-9_]{3,20}$/;

// ------------------------------------------------------------------ auth
app.post('/api/auth/register', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!USERNAME_RE.test(username)) return res.status(400).json({ error: 'invalid username' });
    if (password.length < 6) return res.status(400).json({ error: 'password too short' });

    const exists = await pool.query('SELECT 1 FROM users WHERE username = $1', [username]);
    if (exists.rows.length) return res.status(409).json({ error: 'username taken' });

    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [username, hash]);

    const token = newToken();
    await pool.query('INSERT INTO sessions (token, username) VALUES ($1, $2)', [token, username]);
    res.json({ token, username });
  } catch (e) {
    console.error('register error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const r = await pool.query('SELECT password_hash FROM users WHERE username = $1', [username]);
    if (!r.rows.length) return res.status(401).json({ error: 'invalid credentials' });

    const ok = await bcrypt.compare(password, r.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });

    const token = newToken();
    await pool.query('INSERT INTO sessions (token, username) VALUES ($1, $2)', [token, username]);
    res.json({ token, username });
  } catch (e) {
    console.error('login error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  const token = getToken(req);
  if (token) await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
  res.json({ ok: true });
});

app.get('/api/auth/me', async (req, res) => {
  const username = await getUserFromToken(getToken(req));
  if (!username) return res.status(401).json({ error: 'not authenticated' });
  res.json({ username });
});

// -------------------------------------------------------------------- kv
// Mirrors window.storage: GET/PUT/DELETE a key, optionally shared across all users.
app.get('/api/kv/:key', async (req, res) => {
  const key = req.params.key;
  const shared = req.query.shared === 'true';
  try {
    if (shared) {
      const r = await pool.query('SELECT value FROM kv_shared WHERE key = $1', [key]);
      if (!r.rows.length) return res.status(404).json({ error: 'not found' });
      return res.json({ key, value: r.rows[0].value, shared: true });
    }
    const username = await getUserFromToken(getToken(req));
    if (!username) return res.status(401).json({ error: 'not authenticated' });
    const r = await pool.query('SELECT value FROM kv_personal WHERE username = $1 AND key = $2', [username, key]);
    if (!r.rows.length) return res.status(404).json({ error: 'not found' });
    res.json({ key, value: r.rows[0].value, shared: false });
  } catch (e) {
    console.error('kv get error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

app.put('/api/kv/:key', async (req, res) => {
  const key = req.params.key;
  const shared = req.query.shared === 'true';
  const value = req.body && typeof req.body.value === 'string' ? req.body.value : JSON.stringify(req.body.value);
  if (value === undefined) return res.status(400).json({ error: 'missing value' });
  try {
    if (shared) {
      // Shared writes still require SOME authenticated user (prevents anonymous
      // abuse), and writes to another user's own "user:<username>" profile
      // blob are blocked outright — only that user may modify their own record.
      const username = await getUserFromToken(getToken(req));
      if (!username) return res.status(401).json({ error: 'not authenticated' });
      if (key.startsWith('user:') && key !== 'user:' + username) {
        return res.status(403).json({ error: "cannot modify another user's profile" });
      }
      await pool.query(
        `INSERT INTO kv_shared (key, value, updated_at) VALUES ($1, $2, now())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
        [key, value]
      );
      return res.json({ key, value, shared: true });
    }
    const username = await getUserFromToken(getToken(req));
    if (!username) return res.status(401).json({ error: 'not authenticated' });
    await pool.query(
      `INSERT INTO kv_personal (username, key, value, updated_at) VALUES ($1, $2, $3, now())
       ON CONFLICT (username, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [username, key, value]
    );
    res.json({ key, value, shared: false });
  } catch (e) {
    console.error('kv put error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

app.delete('/api/kv/:key', async (req, res) => {
  const key = req.params.key;
  const shared = req.query.shared === 'true';
  try {
    if (shared) {
      const username = await getUserFromToken(getToken(req));
      if (!username) return res.status(401).json({ error: 'not authenticated' });
      if (key.startsWith('user:') && key !== 'user:' + username) {
        return res.status(403).json({ error: "cannot modify another user's profile" });
      }
      await pool.query('DELETE FROM kv_shared WHERE key = $1', [key]);
      return res.json({ key, deleted: true, shared: true });
    }
    const username = await getUserFromToken(getToken(req));
    if (!username) return res.status(401).json({ error: 'not authenticated' });
    await pool.query('DELETE FROM kv_personal WHERE username = $1 AND key = $2', [username, key]);
    res.json({ key, deleted: true, shared: false });
  } catch (e) {
    console.error('kv delete error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ----------------------------------------------------- broker: Alpaca (real)
// This is a genuine integration with Alpaca's real Trading API — defaults to
// their paper-trading environment (https://paper-api.alpaca.markets), which
// is free, uses simulated money, and is explicitly designed by Alpaca for
// exactly this kind of algo-trading development use case. Nothing here
// places real-money trades unless someone deliberately points baseUrl at
// Alpaca's live API domain with live credentials, which the app's UI never does.
app.post('/api/broker/alpaca/connect', requireAuth, async (req, res) => {
  const { apiKeyId, apiSecretKey } = req.body;
  if (!apiKeyId || !apiSecretKey) return res.status(400).json({ error: 'apiKeyId and apiSecretKey are required' });
  const targetBaseUrl = ALPACA_BASE_URL_DEFAULT.replace(/\/$/, '');
  try {
    const alpacaRes = await alpacaRequest(targetBaseUrl, apiKeyId, apiSecretKey, '/v2/account');
    if (alpacaRes.status === 401 || alpacaRes.status === 403) {
      return res.status(400).json({ error: 'Alpaca rejected these credentials — check your API Key ID and Secret Key.' });
    }
    if (!alpacaRes.ok) {
      const text = await alpacaRes.text().catch(() => '');
      return res.status(502).json({ error: 'Alpaca returned an unexpected error.', detail: text.slice(0, 300) });
    }
    const account = await alpacaRes.json();
    const encSecret = encryptSecret(apiSecretKey);
    await pool.query(
      `INSERT INTO broker_credentials (username, broker, api_key_id, api_secret_enc, base_url, connected_at)
       VALUES ($1, 'alpaca', $2, $3, $4, now())
       ON CONFLICT (username, broker) DO UPDATE SET api_key_id = EXCLUDED.api_key_id, api_secret_enc = EXCLUDED.api_secret_enc, base_url = EXCLUDED.base_url, connected_at = now()`,
      [req.username, apiKeyId, encSecret, targetBaseUrl]
    );
    res.json({
      connected: true,
      account: {
        accountNumber: account.account_number, status: account.status, currency: account.currency,
        cash: account.cash, buyingPower: account.buying_power, portfolioValue: account.portfolio_value,
        equity: account.equity, tradingBlocked: account.trading_blocked,
      },
    });
  } catch (e) {
    console.error('alpaca connect error:', e.message);
    res.status(502).json({ error: 'Could not reach Alpaca — check your network or try again.' });
  }
});

app.get('/api/broker/alpaca/account', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT api_key_id, api_secret_enc, base_url FROM broker_credentials WHERE username=$1 AND broker=$2', [req.username, 'alpaca']);
    if (!r.rows.length) return res.status(404).json({ error: 'Alpaca is not connected for this account.' });
    const { api_key_id, api_secret_enc, base_url } = r.rows[0];
    const apiSecretKey = decryptSecret(api_secret_enc);
    const alpacaRes = await alpacaRequest(base_url, api_key_id, apiSecretKey, '/v2/account');
    if (!alpacaRes.ok) return res.status(502).json({ error: 'Could not fetch account from Alpaca.' });
    const account = await alpacaRes.json();
    res.json({
      account: {
        accountNumber: account.account_number, status: account.status, currency: account.currency,
        cash: account.cash, buyingPower: account.buying_power, portfolioValue: account.portfolio_value,
        equity: account.equity, tradingBlocked: account.trading_blocked,
      },
    });
  } catch (e) {
    console.error('alpaca account error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

app.get('/api/broker/alpaca/positions', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT api_key_id, api_secret_enc, base_url FROM broker_credentials WHERE username=$1 AND broker=$2', [req.username, 'alpaca']);
    if (!r.rows.length) return res.status(404).json({ error: 'Alpaca is not connected for this account.' });
    const { api_key_id, api_secret_enc, base_url } = r.rows[0];
    const apiSecretKey = decryptSecret(api_secret_enc);
    const alpacaRes = await alpacaRequest(base_url, api_key_id, apiSecretKey, '/v2/positions');
    if (!alpacaRes.ok) return res.status(502).json({ error: 'Could not fetch positions from Alpaca.' });
    const positions = await alpacaRes.json();
    res.json({ positions });
  } catch (e) {
    console.error('alpaca positions error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/broker/alpaca/order', requireAuth, async (req, res) => {
  const { symbol, qty, side, type, time_in_force } = req.body;
  if (!symbol || !qty || !side) return res.status(400).json({ error: 'symbol, qty and side are required' });
  try {
    const r = await pool.query('SELECT api_key_id, api_secret_enc, base_url FROM broker_credentials WHERE username=$1 AND broker=$2', [req.username, 'alpaca']);
    if (!r.rows.length) return res.status(404).json({ error: 'Alpaca is not connected for this account.' });
    const { api_key_id, api_secret_enc, base_url } = r.rows[0];
    const apiSecretKey = decryptSecret(api_secret_enc);
    const orderBody = {
      symbol: String(symbol).toUpperCase(),
      qty: String(qty),
      side: side === 'sell' ? 'sell' : 'buy',
      type: type || 'market',
      time_in_force: time_in_force || 'day',
    };
    const alpacaRes = await alpacaRequest(base_url, api_key_id, apiSecretKey, '/v2/orders', {
      method: 'POST', body: JSON.stringify(orderBody),
    });
    const data = await alpacaRes.json().catch(() => ({}));
    if (!alpacaRes.ok) return res.status(400).json({ error: data.message || 'Alpaca rejected this order.', detail: data });
    res.json({ order: data });
  } catch (e) {
    console.error('alpaca order error:', e.message);
    res.status(500).json({ error: 'server error' });
  }
});

app.delete('/api/broker/alpaca/disconnect', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM broker_credentials WHERE username=$1 AND broker=$2', [req.username, 'alpaca']);
    res.json({ disconnected: true });
  } catch (e) {
    res.status(500).json({ error: 'server error' });
  }
});

// SPA fallback: serve index.html for any non-API route
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'not found' });
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// --------------------------------------------------------- schema + start
// Applies schema.sql on every boot. Every statement in it is idempotent
// (CREATE TABLE/INDEX IF NOT EXISTS), so this is safe to run on first deploy
// AND on every restart afterward — no manual database setup step required.
async function initSchema() {
  const schemaPath = path.join(__dirname, 'schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf8');
  await pool.query(sql);
  console.log('Database schema verified.');
}

async function start() {
  const maxAttempts = 10;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await initSchema();
      break;
    } catch (e) {
      if (attempt === maxAttempts) {
        console.error('FATAL: could not apply database schema after', maxAttempts, 'attempts:', e.message);
        process.exit(1);
      }
      console.log(`Database not ready yet (attempt ${attempt}/${maxAttempts}), retrying in 3s...`);
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  app.listen(PORT, () => {
    console.log(`VaticTrader server listening on port ${PORT}`);
  });
}

start();
