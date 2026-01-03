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

    console.log('='.repeat(60));
    console.log('🔑 TOKEN EXCHANGE ATTEMPT');
    console.log(`Redirect URI: [${redirectUri}]`);
    console.log('='.repeat(60));

    // Dual-method: Try Basic Auth first, then fallback to body params
    let tokenResponse;
    const basicAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

    const baseParams = {
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      code_verifier: session.codeVerifier,
    };

    try {
      // Method 1: Basic Auth (preferred for confidential clients)
      tokenResponse = await axios.post(
        'https://auth.fanvue.com/oauth2/token',
        new URLSearchParams(baseParams),
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
    } catch (basicError) {
      console.log('Basic Auth failed, trying with client_id/secret in body...');
      // Method 2: client_id + client_secret in body (fallback)
      tokenResponse = await axios.post(
        'https://auth.fanvue.com/oauth2/token',
        new URLSearchParams({
          ...baseParams,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'User-Agent': 'Fanvue-API-Client/1.0'
          },
          timeout: 30000
        }
      );
    }

    console.log('✅ Token exchange successful');
    console.log('Access Token (preview):', tokenResponse.data.access_token.substring(0, 20) + '...');

    const apiHeaders = {
      'Authorization': `Bearer ${tokenResponse.data.access_token}`,
      'X-Fanvue-API-Version': '2025-06-26',
      'Accept': 'application/json',
      'User-Agent': 'Fanvue-API-Client/1.0'
    };

    const profileResponse = await axios.get('https://api.fanvue.com/users/me', { headers: apiHeaders });
    const creatorData = profileResponse.data || {};
    const creatorName = creatorData.displayName || creatorData.handle || 'Unknown Creator';
    const profilePic = creatorData.avatarUrl || '';

    const subscribersResponse = await axios.get('https://api.fanvue.com/v1/creator/subscribers', {
      params: { page: 1, size: 50 },
      headers: apiHeaders,
    });
    const subscribers = subscribersResponse.data.data || [];

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Fanvue Connected</title>
        <style>
          body { font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 20px; color: #333; }
          .container { max-width: 900px; margin: 40px auto; background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; }
          .profile-section { display: flex; flex-direction: column; align-items: center; margin: -70px auto 40px; }
          .profile-section img { width: 160px; height: 160px; border-radius: 50%; object-fit: cover; border: 6px solid white; box-shadow: 0 8px 25px rgba(0,0,0,0.2); }
          .no-photo { width: 160px; height: 160px; background: #ccc; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: #666; font-size: 1.4em; border: 6px solid white; }
          .info { text-align: center; padding: 20px; }
          .info h1 { margin: 15px 0; font-size: 2.4em; color: #333; }
          .stats { display: flex; justify-content: center; gap: 40px; margin: 40px 0; }
          .stat-box { background: #f8f9fa; padding: 25px; border-radius: 12px; min-width: 200px; text-align: center; box-shadow: 0 4px 10px rgba(0,0,0,0.05); }
          .stat-box strong { font-size: 2.5em; display: block; color: #667eea; }
          footer { text-align: center; padding: 30px; color: #888; }
          a { color: #667eea; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header"><h1>✅ Fanvue API Connected Successfully!</h1></div>
          <div class="profile-section">
            ${profilePic ? `<img src="${profilePic}" alt="${creatorName}">` : '<div class="no-photo">No Photo</div>'}
            <div class="info"><h1>${creatorName}</h1><p>Deployment working perfectly</p></div>
          </div>
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
    console.error('='.repeat(60));
    console.error('🔥 AUTHENTICATION FAILED');
    console.error('Status:', error.response?.status);
    console.error('Data:', error.response?.data);
    console.error('='.repeat(60));

    res.status(500).send(`
      <!DOCTYPE html>
      <html><head><meta charset="UTF-8"><title>Auth Failed</title>
      <style>body{font-family:Arial;background:#f8f9fa;padding:40px;color:#333;}
      .container{max-width:800px;margin:auto;background:white;padding:40px;border-radius:16px;box-shadow:0 4px 15px rgba(0,0,0,0.1);}
      .error{background:#f8d7da;color:#721c24;padding:20px;border-radius:8px;margin-bottom:30px;}
      .fix{background:#d1ecf1;color:#0c5460;padding:25px;border-radius:12px;}
      code{background:#eee;padding:2px 6px;border-radius:4px;}
      </style></head>
      <body>
        <div class="container">
          <div class="error"><h1>❌ Authentication Failed</h1>
          <p><strong>Error:</strong> ${error.response?.data?.error_description || error.message}</p>
          <p>Status: ${error.response?.status || 'Unknown'}</p></div>
          <div class="fix"><h2>Check These:</h2>
          <ol>
            <li>Redirect URI in Fanvue Dashboard: <code>https://fanvue-proxy2.onrender.com/oauth/callback</code></li>
            <li>CLIENT_ID and CLIENT_SECRET in Render env vars match exactly</li>
            <li>Clear browser cookies and retry</li>
          </ol></div>
          <p style="text-align:center;margin-top:40px;">
            <a href="/oauth/start" style="background:#007bff;color:white;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:bold;">Retry Login</a>
          </p>
        </div>
      </body></html>
    `);
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Fixed catch-all route for SPA
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
