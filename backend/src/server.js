'use strict';

const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Redis = require('ioredis');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const FRONTEND_URL = (process.env.FRONTEND_URL || 'http://localhost:8080').replace(/\/$/, '');
const PENDING_TTL_SECONDS = Math.max(60, Number(process.env.PENDING_TTL_SECONDS || 1800));

const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
  maxRetriesPerRequest: 3,
  enableReadyCheck: true
});
redis.on('error', (err) => console.error('Redis connection error:', err.message));

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
pool.on('error', (err) => console.error('PostgreSQL pool error:', err.message));

const smtpConfigured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
const mailer = smtpConfigured
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    })
  : null;

app.use(helmet());
app.use(express.json({ limit: '20kb' }));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', FRONTEND_URL);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please wait and try again.' }
});
app.use(['/api/register', '/api/verify-email', '/api/login'], authLimiter);

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}
function tokenHash(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}
function publicUser(row) {
  return { id: row.id, name: row.name, email: row.email, emailVerified: true };
}

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    await redis.ping();
    res.json({ status: 'ok', database: 'connected', redis: 'connected' });
  } catch (err) {
    console.error('Health check failed:', err.message);
    res.status(503).json({ status: 'unavailable' });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');

    if (name.length < 2 || name.length > 100) {
      return res.status(400).json({ error: 'Name must be between 2 and 100 characters.' });
    }
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({ error: 'Password must be 8–128 characters long.' });
    }

    const existing = await pool.query('SELECT 1 FROM users WHERE email = $1', [email]);
    if (existing.rowCount) {
      return res.status(409).json({ error: 'An account with this email already exists. Please log in.' });
    }

    const pendingKey = `pending-registration:${email}`;
    const existingPending = await redis.get(pendingKey);
    if (existingPending) {
      return res.status(409).json({ error: 'A verification email was already requested. Check your inbox or wait for the pending request to expire.' });
    }

    // Hash the password immediately; never store a plaintext password in Redis or PostgreSQL.
    const passwordHash = await bcrypt.hash(password, 12);
    const rawToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = tokenHash(rawToken);

    // Redis stores the pending registration temporarily. TTL removes it if not verified.
    const pending = JSON.stringify({
      name,
      email,
      passwordHash,
      tokenHash: hashedToken,
      createdAt: new Date().toISOString()
    });
    await redis.set(pendingKey, pending, 'EX', PENDING_TTL_SECONDS, 'NX');

    if (!mailer) {
      await redis.del(pendingKey);
      console.error('SMTP is not configured; registration email cannot be sent.');
      return res.status(503).json({ error: 'Email delivery is not configured on the server. Set SMTP_HOST, SMTP_USER, and SMTP_PASS, then try again.' });
    }

    const verifyUrl = `${FRONTEND_URL}/?token=${encodeURIComponent(rawToken)}`;
    try {
      await mailer.sendMail({
        from: process.env.MAIL_FROM || process.env.SMTP_USER,
        to: email,
        subject: 'Verify your email address',
        text: `Hello ${name},\n\nVerify your email address by opening this link:\n${verifyUrl}\n\nThis link expires in ${Math.round(PENDING_TTL_SECONDS / 60)} minutes. If you did not request this, you can ignore this email.`,
        html: `<p>Hello ${escapeHtml(name)},</p><p>Please verify your email address by clicking the button below.</p><p><a href="${verifyUrl}" style="display:inline-block;padding:12px 18px;background:#2563eb;color:white;text-decoration:none;border-radius:6px">Verify email</a></p><p>This link expires in ${Math.round(PENDING_TTL_SECONDS / 60)} minutes. If you did not request this, you can ignore this email.</p>`
      });
    } catch (mailErr) {
      await redis.del(pendingKey);
      console.error('Email send failed:', mailErr.message);
      return res.status(502).json({ error: 'Could not send the verification email. Check SMTP settings and try again.' });
    }

    res.status(202).json({ message: 'Registration started. Check your email for the verification link.' });
  } catch (err) {
    console.error('Registration error:', err.message);
    res.status(500).json({ error: 'Something went wrong while registering.' });
  }
});

app.post('/api/verify-email', async (req, res) => {
  const rawToken = String(req.body.token || '');
  if (!/^[a-f0-9]{64}$/i.test(rawToken)) {
    return res.status(400).json({ error: 'This verification link is invalid or expired.' });
  }

  try {
    const presentedHash = tokenHash(rawToken);
    // We do not know the email from the link, so scan only pending-registration keys.
    // For this small demo, use SCAN rather than KEYS to avoid blocking Redis.
    let cursor = '0';
    do {
      const [nextCursor, keys] = await redis.scan(cursor, 'MATCH', 'pending-registration:*', 'COUNT', 100);
      cursor = nextCursor;
      for (const key of keys) {
        const value = await redis.get(key);
        if (!value) continue;
        let pending;
        try { pending = JSON.parse(value); } catch { await redis.del(key); continue; }
        if (pending.tokenHash !== presentedHash) continue;

        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          await client.query(
            `INSERT INTO users (name, email, password_hash, email_verified_at)
             VALUES ($1, $2, $3, NOW())
             ON CONFLICT (email) DO NOTHING`,
            [pending.name, pending.email, pending.passwordHash]
          );
          const result = await client.query(
            'SELECT id, name, email, email_verified_at FROM users WHERE email = $1',
            [pending.email]
          );
          await client.query('COMMIT');
          await redis.del(key); // One-time token: remove pending data after successful verification.
          if (!result.rowCount || !result.rows[0].email_verified_at) {
            return res.status(500).json({ error: 'Could not complete email verification.' });
          }
          return res.json({ message: 'Email verified successfully. You can now log in.' });
        } catch (dbErr) {
          await client.query('ROLLBACK');
          throw dbErr;
        } finally {
          client.release();
        }
      }
    } while (cursor !== '0');

    return res.status(400).json({ error: 'This verification link is invalid, already used, or expired.' });
  } catch (err) {
    console.error('Verification error:', err.message);
    return res.status(500).json({ error: 'Something went wrong while verifying your email.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    if (!validEmail(email) || !password) {
      return res.status(400).json({ error: 'Enter your email and password.' });
    }

    const result = await pool.query(
      'SELECT id, name, email, password_hash, email_verified_at FROM users WHERE email = $1',
      [email]
    );
    if (!result.rowCount) return res.status(401).json({ error: 'Invalid email or password.' });

    const user = result.rows[0];
    // Only verified users are inserted into this table by the verification flow.
    if (!user.email_verified_at) {
      return res.status(403).json({ error: 'Please verify your email before logging in.' });
    }
    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatches) return res.status(401).json({ error: 'Invalid email or password.' });

    // Demo login response only. For production, add server-side sessions or short-lived JWTs.
    return res.json({ message: `Welcome back, ${user.name}!`, user: publicUser(user) });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Something went wrong while logging in.' });
  }
});

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[ch]);
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`API listening on port ${PORT}`);
});
