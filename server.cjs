require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;

// Trust Render's reverse proxy for correct protocol/host
app.set('trust proxy', true);

// Load and trim credentials
const CLIENT_ID = (process.env.CLIENT_ID || '').trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || '').trim();

// Startup logging
console.log('='.repeat(60));
console.log('🚀 FANVUE SERVER STARTING');
console.log('='.repeat(60));
console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
console.log(`Node version: ${process.version}`);
console.log(`Client ID length: ${CLIENT_ID.length}`);
console.log(`Client Secret length: ${CLIENT_SECRET.length}`);
console.log(`Port: ${PORT}`);
console.log('='.repeat(60));

// Simple in-memory session store for PKCE state
const sessions = new Map();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// CORS preflight
app.options('/*', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.sendStatus(200);
});

// Guard: Block OAuth routes if credentials missing
if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error('❌ Missing CLIENT_ID or CLIENT_SECRET – OAuth routes disabled');
  app.get('/oauth/start', (req, res) => {
    res.status(503).send(`
      <h1>Server Misconfigured</h1>
      <p>Missing Fanvue OAuth credentials.</p>
      <p>Set <code>CLIENT_ID</code> and <code>CLIENT_SECRET</code> in Render environment variables.</p>
    `);
  });
} else {
  // OAuth initiation
  app.get('/oauth/start', (req, res) => {
    const state = crypto.randomBytes(16).toString('hex');
    const nonce = crypto.randomBytes(16).toString('hex');
    const codeVerifier = crypto
      .randomBytes(32)
      .toString('base64url')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    sessions.set(state, { nonce, codeVerifier, timestamp: Date.now() });

    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    const redirectUri = `${req.protocol}://${req.get('host')}/oauth/callback`;

    console.log('='.repeat(60));
    console.log('🔗 AUTHORIZATION REQUEST');
    console.log(`Redirect URI: ${redirectUri}`);
    console.log('='.repeat(60));

    const authUrl = new URL('https://auth.fanvue.com/oauth2/auth');
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('client_id', CLIENT_ID);
    authUrl.searchParams.append('redirect_uri', redirectUri);
    authUrl.searchParams.append('scope', 'openid offline_access read:self read:fan read:insights');
    authUrl.searchParams.append('state', state);
    authUrl.searchParams.append('nonce', nonce);
    authUrl.searchParams.append('code_challenge', codeChallenge);
    authUrl.searchParams.append('code_challenge_method', 'S256');

    res.redirect(authUrl.toString());
  });
}

// OAuth callback – always registered (even if creds missing, for better errors)
app.get('/oauth/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state) {
    return res.status(400).send('<h1>Missing code or state</h1><a href="/oauth/start">← Retry</a>');
  }

  const session = sessions.get(state);
  if (!session) {
    return res.status(400).send('<h1>Invalid or expired state</h1><a href="/oauth/start">← Restart</a>');
  }

  sessions.delete(state);

  if (!CLIENT_ID || !CLIENT_SECRET) {
    return res.status(503).send('<h1>Server Misconfigured</h1><p>Missing OAuth credentials.</p>');
  }

  try {
    const redirectUri = `${req.protocol}://${req.get('host')}/oauth/callback`;

    const basicAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

    const tokenResponse = await axios.post(
      'https://auth.fanvue.com/oauth2/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        code_verifier: session.codeVerifier,
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${basicAuth}`,
          'Accept': 'application/json',
          'User-Agent': 'Fanvue-API-Client/1.0',
        },
        timeout: 30000,
      }
    );

    const { access_token } = tokenResponse.data;

    const apiHeaders = {
      Authorization: `Bearer ${access_token}`,
      'X-Fanvue-API-Version': '2025-06-26',
      Accept: 'application/json',
      'User-Agent': 'Fanvue-API-Client/1.0',
    };

    // Fetch creator profile
    const profileResponse = await axios.get('https://api.fanvue.com/users/me', { headers: apiHeaders });
    const creatorData = profileResponse.data;

    const creatorName = creatorData.displayName || creatorData.handle || 'Unknown Creator';
    const profilePic = creatorData.avatarUrl || '';

    // Fetch first page of subscribers
    const subscribersResponse = await axios.get('https://api.fanvue.com/v1/creator/subscribers', {
      params: { page: 1, size: 50 },
      headers: apiHeaders,
    });
    const subscribers = subscribersResponse.data.data || [];

    // Success page
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Fanvue Connected</title>
        <style>
          body { font-family: system-ui, sans-serif; background: #f0f2f5; color: #333; padding: 20px; }
          .container { max-width: 900px; margin: 40px auto; background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 40px; text-align: center; }
          .profile-section { text-align: center; margin: -60px auto 40px; }
          img { width: 140px; height: 140px; border-radius: 50%; border: 6px solid white; box-shadow: 0 8px 25px rgba(0,0,0,0.2); }
          .stats { display: flex; justify-content: center; gap: 30px; flex-wrap: wrap; padding: 20px; }
          .stat { background: #f8f9fa; padding: 20px; border-radius: 12px; min-width: 180px; text-align: center; }
          .stat strong { font-size: 2.2em; display: block; color: #667eea; }
          footer { text-align: center; padding: 30px; color: #666; }
          a { color: #667eea; text-decoration: none; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header"><h1>✅ Fanvue API Connected!</h1></div>
          <div class="profile-section">
            ${profilePic ? `<img src="${profilePic}" alt="Profile">` : '<div style="width:140px;height:140px;background:#ccc;border-radius:50%;margin:0 auto;"></div>'}
            <h2>${creatorName}</h2>
          </div>
          <div class="stats">
            <div class="stat"><strong>${subscribers.length}</strong><div>Subscribers (Page 1)</div></div>
            <div class="stat"><strong>${creatorData.fanCounts?.followersCount || 0}</strong><div>Followers</div></div>
            <div class="stat"><strong>${creatorData.fanCounts?.subscribersCount || 0}</strong><div>Total Subscribers</div></div>
          </div>
          <footer>
            <a href="/">← Back to Dashboard</a> | <a href="/oauth/start">Login Again</a>
          </footer>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('🔥 Token exchange failed:', error.response?.data || error.message);

    const errorMsg = error.response?.data?.error_description || error.message || 'Unknown error';

    res.status(500).send(`
      <!DOCTYPE html>
      <html><head><title>Auth Failed</title><style>body{font-family:system-ui,sans-serif;padding:40px;background:#f8f9fa;}</style></head>
      <body>
        <h1>❌ Authentication Failed</h1>
        <p><strong>Error:</strong> ${errorMsg}</p>
        <p>Common causes:</p>
        <ul>
          <li>Redirect URI mismatch in Fanvue dashboard</li>
          <li>Invalid or revoked Client ID/Secret</li>
          <li>Browser cookies not cleared</li>
        </ul>
        <p><a href="/oauth/start">← Retry Authentication</a></p>
      </body>
      </html>
    `);
  }
});

// Serve dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Fallback for SPA routing
app.get('/*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('✅ FANVUE SERVER READY');
  console.log('='.repeat(60));
  console.log(`Server running on port ${PORT}`);
  console.log(`Dashboard: https://fanvue-proxy2.onrender.com`);
  console.log(`OAuth Start: https://fanvue-proxy2.onrender.com/oauth/start`);
  console.log(`Redirect URI: https://fanvue-proxy2.onrender.com/oauth/callback`);
  console.log('='.repeat(60));
});
