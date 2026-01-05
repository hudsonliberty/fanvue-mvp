// server.cjs — Fanvue MVP (OAuth + Profile in Dashboard + Webhooks)

require('dotenv').config();

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 10000;

app.set('trust proxy', true);

const CLIENT_ID = (process.env.CLIENT_ID || '').trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || '').trim();
const ADMIN_TOKEN = (process.env.ADMIN_TOKEN || '').trim();

const COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'fanvue_oauth';
const SESSION_SECRET = (process.env.SESSION_SECRET || 'change-me').trim();

// --- In-memory stores (ok for MVP; Render restarts clears sessions) ---
const oauthStates = new Map(); // state -> { codeVerifier, nonce, ts }
const sessions = new Map();    // sid -> { accessToken, creator, ts }
const webhookEvents = [];      // latest events (memory)
const MAX_EVENTS = 50;

// --- Middleware ---
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(SESSION_SECRET));
app.use(express.static(path.join(__dirname, 'public')));

// --- Helpers ---
function baseUrl(req) {
  // Render terminates TLS at proxy; trust proxy enabled.
  return `https://${req.get('host')}`;
}

function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return next(); // if you don't set it, admin auth is disabled
  const got = (req.get('x-admin-token') || '').trim();
  if (got && got === ADMIN_TOKEN) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

function getSession(req) {
  const sid = req.signedCookies?.[COOKIE_NAME];
  if (!sid) return null;
  return sessions.get(sid) || null;
}

function setSessionCookie(res, sid) {
  res.cookie(COOKIE_NAME, sid, {
    signed: true,
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/'
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: '/' });
}

function addEvent(evt) {
  webhookEvents.unshift(evt);
  if (webhookEvents.length > MAX_EVENTS) webhookEvents.length = MAX_EVENTS;
}

// --- Startup log ---
console.log('='.repeat(60));
console.log('FANVUE MVP STARTING');
console.log('='.repeat(60));
console.log(`NODE_ENV: ${process.env.NODE_ENV || 'development'}`);
console.log(`CLIENT_ID present: ${!!CLIENT_ID}`);
console.log(`CLIENT_SECRET present: ${!!CLIENT_SECRET}`);
console.log(`ADMIN_TOKEN present: ${!!ADMIN_TOKEN}`);
console.log(`PORT: ${PORT}`);
console.log('='.repeat(60));

// --- Routes ---

// Dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Health
app.get('/health', (req, res) => res.status(200).send('ok'));

// OAuth start
app.get('/oauth/start', (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    return res.status(503).send('Missing CLIENT_ID / CLIENT_SECRET in environment.');
  }

  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');

  const codeVerifier = crypto.randomBytes(32).toString('base64url')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  const codeChallenge = crypto.createHash('sha256')
    .update(codeVerifier)
    .digest('base64url')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  oauthStates.set(state, { nonce, codeVerifier, ts: Date.now() });

  const redirectUri = `${baseUrl(req)}/oauth/callback`;

  const authUrl = new URL('https://auth.fanvue.com/oauth2/auth');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', 'openid offline_access read:self read:fan read:insights');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('nonce', nonce);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  return res.redirect(authUrl.toString());
});

// OAuth callback
app.get('/oauth/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state) {
    return res.status(400).send('Missing code/state');
  }

  const st = oauthStates.get(state);
  if (!st) {
    return res.status(400).send('Invalid/expired state. Restart login.');
  }
  oauthStates.delete(state);

  try {
    const redirectUri = `${baseUrl(req)}/oauth/callback`;
    const basicAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

    const tokenResp = await axios.post(
      'https://auth.fanvue.com/oauth2/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        code_verifier: st.codeVerifier
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${basicAuth}`
        },
        timeout: 20000
      }
    );

    const accessToken = tokenResp.data.access_token;
    if (!accessToken) throw new Error('No access_token returned');

    const apiHeaders = {
      Authorization: `Bearer ${accessToken}`,
      'X-Fanvue-API-Version': '2025-06-26'
    };

    // Creator profile
    const profileResp = await axios.get('https://api.fanvue.com/users/me', {
      headers: apiHeaders,
      timeout: 20000
    });

    const creator = profileResp.data || {};
    const creatorName = creator.displayName || creator.handle || 'Creator';

    // Store session
    const sid = crypto.randomBytes(24).toString('hex');
    sessions.set(sid, {
      accessToken,
      creator,
      ts: Date.now()
    });
    setSessionCookie(res, sid);

    // Success page -> back to dashboard
    return res.send(`
      <!doctype html>
      <html>
        <head>
          <meta name="viewport" content="width=device-width,initial-scale=1"/>
          <title>Connected</title>
          <style>
            body{font-family:system-ui;background:#0b0b10;color:#e9e9f1;display:grid;place-items:center;height:100vh;margin:0}
            .box{max-width:560px;width:92%;background:#10101a;border:1px solid #232338;border-radius:16px;padding:22px;text-align:center}
            .btn{display:inline-block;margin-top:14px;padding:10px 14px;border-radius:10px;background:linear-gradient(135deg,#6d28d9,#ff2d8d);color:#fff;text-decoration:none;font-weight:700}
            img{width:120px;height:120px;border-radius:999px;object-fit:cover;border:4px solid #10101a;box-shadow:0 10px 30px rgba(0,0,0,.35)}
          </style>
        </head>
        <body>
          <div class="box">
            <h2>Fanvue Connected Successfully!</h2>
            ${creator.avatarUrl ? `<img src="${creator.avatarUrl}" alt="avatar">` : ''}
            <div style="opacity:.85;margin-top:10px">${creatorName}</div>
            <a class="btn" href="/">Go to Dashboard</a>
          </div>
        </body>
      </html>
    `);
  } catch (err) {
    const status = err?.response?.status;
    const data = err?.response?.data;
    console.error('OAuth callback failed:', status, data || err.message);
    return res.status(500).send('Authentication failed. Check Render logs.');
  }
});

// API: me (dashboard uses this to show username + avatar)
app.get('/api/me', (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: 'Not authenticated' });

  const c = s.creator || {};
  return res.json({
    username: c.displayName || c.handle || 'Creator',
    handle: c.handle ? `@${c.handle.replace(/^@/, '')}` : '',
    avatar_url: c.avatarUrl || ''
  });
});

// API: logout
app.post('/api/logout', (req, res) => {
  const sid = req.signedCookies?.[COOKIE_NAME];
  if (sid) sessions.delete(sid);
  clearSessionCookie(res);
  return res.json({ ok: true });
});

// Webhook endpoint (Fanvue POSTs here)
// IMPORTANT: Fanvue needs POST. Browsers hitting it will GET. We handle both.
app.get('/webhooks/fanvue', (req, res) => res.status(200).send('ok'));

app.post('/webhooks/fanvue', (req, res) => {
  const evt = {
    ts: Date.now(),
    headers: req.headers,
    body: req.body
  };
  addEvent(evt);
  console.log('✅ Fanvue webhook received:', {
    type: req.body?.type,
    id: req.body?.data?.id || req.body?.id
  });
  return res.status(200).send('ok');
});

// API: events (dashboard pulls last webhook payloads)
app.get('/api/events', (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: 'Not authenticated' });
  return res.json({ count: webhookEvents.length, events: webhookEvents });
});

// Optional: clear events (admin)
app.post('/api/events/clear', requireAdmin, (req, res) => {
  webhookEvents.length = 0;
  return res.json({ ok: true });
});

// SPA fallback -> dashboard
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('SERVER READY');
  console.log('='.repeat(60));
  console.log(`Dashboard:  https://fanvue-proxy2.onrender.com/`);
  console.log(`OAuth Start: https://fanvue-proxy2.onrender.com/oauth/start`);
  console.log(`Callback:    https://fanvue-proxy2.onrender.com/oauth/callback`);
  console.log(`Webhook:     https://fanvue-proxy2.onrender.com/webhooks/fanvue`);
  console.log('='.repeat(60));
});
