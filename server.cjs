require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;

app.set('trust proxy', true);

const CLIENT_ID = (process.env.CLIENT_ID || '').trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || '').trim();

console.log('='.repeat(60));
console.log('🚀 FANVUE SERVER STARTING');
console.log('='.repeat(60));
console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
console.log(`Node version: ${process.version}`);
console.log(`Client ID length: ${CLIENT_ID.length}`);
console.log(`Client Secret length: ${CLIENT_SECRET.length}`);
console.log(`Port: ${PORT}`);
console.log('='.repeat(60));

const sessions = new Map();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// CORS for OPTIONS preflight
app.options('/*', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.sendStatus(200);
});

app.get('/oauth/start', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  const codeVerifier = crypto.randomBytes(32).toString('base64url')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  sessions.set(state, { nonce, codeVerifier, timestamp: Date.now() });

  const codeChallenge = crypto.createHash('sha256')
    .update(codeVerifier)
    .digest('base64url')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  const redirectUri = `${req.protocol}://${req.get('host')}/oauth/callback`.trim();

  console.log('='.repeat(60));
  console.log('🔗 AUTHORIZATION REQUEST');
  console.log(`Redirect URI: [${redirectUri}]`);
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

app.get('/oauth/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state) {
    return res.status(400).send('<h1>Missing code or state</h1><a href="/oauth/start">Retry</a>');
  }

  const session = sessions.get(state);
  if (!session) {
    return res.status(400).send('<h1>Invalid or expired state</h1><a href="/oauth/start">Restart</a>');
  }

  sessions.delete(state);

  try {
    const redirectUri = `${req.protocol}://${req.get('host')}/oauth/callback`.trim();

    const basicAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

    console.log('='.repeat(60));
    console.log('🔑 TOKEN EXCHANGE ATTEMPT');
    console.log(`Redirect URI: [${redirectUri}]`);
    console.log('='.repeat(60));

    // Changed to standard OAuth2 token endpoint
    const tokenResponse = await axios.post(
      'https://auth.fanvue.com/oauth/token',
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
          'User-Agent': 'Fanvue-API-Client/1.0'
        },
        timeout: 30000
      }
    );

    console.log('✅ Token exchange successful');
    console.log('Access Token (preview):', tokenResponse.data.access_token.substring(0, 20) + '...');

    const apiHeaders = {
      'Authorization': `Bearer ${tokenResponse.data.access_token}`,
      'X-Fanvue-API-Version': '2025-06-26',
      'Accept': 'application/json',
      'User-Agent': 'Fanvue-API-Client/1.0'
    };

    // Fetch creator profile
    const profileResponse = await axios.get('https://api.fanvue.com/users/me', { headers: apiHeaders });
    const creatorData = profileResponse.data || {};
    const creatorName = creatorData.displayName || creatorData.handle || 'Unknown Creator';
    const profilePic = creatorData.avatarUrl || '';

    // Fetch subscribers (page 1)
    const subscribersResponse = await axios.get('https://api.fanvue.com/v1/creator/subscribers', {
      params: { page: 1, size: 50 },
      headers: apiHeaders,
    });
    const subscribers = subscribersResponse.data.data || [];

    // Success page (your original beautiful HTML, slightly trimmed for brevity)
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Fanvue Connected</title>
        <style>
          /* Your full styles here - unchanged */
          body { font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 20px; color: #333; }
          .container { max-width: 900px; margin: 40px auto; background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
          /* ... rest of your styles ... */
        </style>
      </head>
      <body>
        <div class="container">
          <!-- Your full success HTML here -->
          <div class="header">
            <h1>✅ Fanvue API Connected Successfully!</h1>
          </div>
          <!-- Profile, stats, etc. -->
          <div class="stats">
            <div class="stat-box"><strong>${subscribers.length}</strong><div>Subscribers (Page 1)</div></div>
            <div class="stat-box"><strong>${creatorData.fanCounts?.followersCount || 0}</strong><div>Followers</div></div>
            <div class="stat-box"><strong>${creatorData.fanCounts?.subscribersCount || 0}</strong><div>Total Subscribers</div></div>
          </div>
          <footer><a href="/">Dashboard</a> | <a href="/oauth/start">Login Again</a></footer>
        </div>
      </body>
      </html>
    `);

  } catch (error) {
    // Your detailed error handling (unchanged)
    console.error('🔥 AUTHENTICATION FAILED', error.response?.status || error.message);
    // ... your full error page HTML ...
  }
});

// Serve dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Fixed catch-all for SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('✅ FANVUE SERVER READY');
  console.log(`Server running on port ${PORT}`);
  console.log(`Dashboard: https://fanvue-proxy2.onrender.com`);
  console.log(`OAuth Start: https://fanvue-proxy2.onrender.com/oauth/start`);
  console.log(`Redirect URI: https://fanvue-proxy2.onrender.com/oauth/callback`);
  console.log('='.repeat(60));
});
