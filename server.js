require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// TRUST RENDER'S PROXY HEADERS
app.set('trust proxy', true);

// GET CREDENTIALS FROM ENVIRONMENT VARIABLES
const CLIENT_ID = process.env.CLIENT_ID || '3c1182f1-ef24-49e7-a819-2814d97b8cd7';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'replace-with-real-secret';

const sessions = new Map();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// CORS HANDLER
app.options('/*anything', (req, res) => {
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

  // DYNAMIC REDIRECT URI (WORKS ON RENDER AND LOCALLY)
  const redirectUri = `${req.protocol}://${req.get('host')}/oauth/callback`;

  const authUrl = new URL('https://auth.fanvue.com/oauth2/auth');
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('client_id', CLIENT_ID);
  authUrl.searchParams.append('redirect_uri', redirectUri);
  authUrl.searchParams.append('scope', 'openid offline_access read:self read:fan read:insights');
  authUrl.searchParams.append('state', state);
  authUrl.searchParams.append('nonce', nonce);
  authUrl.searchParams.append('code_challenge', codeChallenge);
  authUrl.searchParams.append('code_challenge_method', 'S256');

  console.log('='.repeat(60));
  console.log('REDIRECTING TO FANVUE AUTH');
  console.log(`URL: ${authUrl.toString()}`);
  console.log(`Redirect URI: ${redirectUri}`);
  console.log('='.repeat(60));

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
    // DYNAMIC REDIRECT URI (WORKS ON RENDER)
    const redirectUri = `${req.protocol}://${req.get('host')}/oauth/callback`;

    console.log('='.repeat(60));
    console.log('EXCHANGING CODE FOR TOKEN');
    console.log('='.repeat(60));

    const basicAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

    const tokenResponse = await axios.post(
      'https://auth.fanvue.com/oauth2/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        code_verifier: session.codeVerifier,
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${basicAuth}`,
        },
      }
    );

    const accessToken = tokenResponse.data.access_token;
    console.log('Token received');

    const apiHeaders = {
      Authorization: `Bearer ${accessToken}`,
      'X-Fanvue-API-Version': '2025-06-26',
    };

    console.log('='.repeat(60));
    console.log('FETCHING CREATOR PROFILE');
    console.log('='.repeat(60));

    const profileResponse = await axios.get('https://api.fanvue.com/users/me', {
      headers: apiHeaders,
    });

    const creatorData = profileResponse.data || {};
    const creatorName = creatorData.displayName || creatorData.handle || 'Unknown Creator';
    const profilePic = creatorData.avatarUrl || '';

    console.log(`Creator Name: ${creatorName}`);
    console.log(`Profile Picture URL: ${profilePic || 'Not found'}`);

    console.log('='.repeat(60));
    console.log('FETCHING SUBSCRIBERS');
    console.log('='.repeat(60));

    const subscribersResponse = await axios.get('https://api.fanvue.com/v1/creator/subscribers', {
      params: { page: 1, size: 50 },
      headers: apiHeaders,
    });

    const subscribers = subscribersResponse.data.data || [];
    console.log(`Found ${subscribers.length} subscribers`);

    // Success page with creator data
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
          .raw { margin: 40px; background: #1e1e1e; color: #f8f8f2; padding: 20px; border-radius: 12px; overflow-x: auto; font-family: 'Courier New', monospace; }
          a { color: #667eea; font-weight: bold; text-decoration: none; }
          footer { text-align: center; padding: 30px; color: #888; font-size: 0.9em; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Fanvue API Connected!</h1>
            <p>Your account data has been successfully retrieved.</p>
          </div>

          <div class="profile-section">
            ${profilePic 
              ? `<img src="${profilePic}" alt="${creatorName}'s Profile Picture">`
              : `<div class="no-photo">No Photo</div>`
            }
            <div class="info">
              <h1>${creatorName}</h1>
              <p>Authenticated Creator</p>
            </div>
          </div>

          <div class="stats">
            <div class="stat-box">
              <strong>${subscribers.length}</strong>
              <div>Subscribers (Page 1)</div>
            </div>
            <div class="stat-box">
              <strong>${creatorData.fanCounts?.followersCount || 0}</strong>
              <div>Followers</div>
            </div>
            <div class="stat-box">
              <strong>${creatorData.fanCounts?.subscribersCount || 0}</strong>
              <div>Total Subscribers</div>
            </div>
          </div>

          <div class="raw">
            <h3>Creator Profile Raw Data</h3>
            <pre>${JSON.stringify(profileResponse.data, null, 2)}</pre>
          </div>

          <div class="raw">
            <h3>Subscribers Raw Data (Page 1)</h3>
            <pre>${JSON.stringify(subscribersResponse.data, null, 2)}</pre>
          </div>

          <footer>
            <p><a href="/">Back to Dashboard</a> | <a href="/oauth/start">Login Again</a></p>
          </footer>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('='.repeat(60));
    console.error('ERROR');
    console.error('='.repeat(60));
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', JSON.stringify(error.response.data, null, 2));
    } else {
      console.error(error.message);
    }

    res.status(500).send(`
      <!DOCTYPE html>
      <html><head><title>Error</title><style>body{background:#f8d7da;color:#721c24;text-align:center;padding:60px;}.box{max-width:700px;margin:auto;background:white;padding:40px;border-radius:12px;}</style></head>
      <body><div class="box"><h1>Something Went Wrong</h1><p>${error.response?.data?.error_description || error.message}</p><pre>${JSON.stringify(error.response?.data || {message: error.message}, null, 2)}</pre><p><a href="/oauth/start">Retry</a></p></div></body></html>
    `);
  }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/*anything', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('RENDER-READY FANVUE SERVER STARTED');
  console.log('='.repeat(60));
  console.log(`Server running on port ${PORT}`);
  console.log(`Local URL: http://localhost:${PORT}`);
  console.log(`Render URL: https://your-app-name.onrender.com (set after deployment)`);
  console.log('='.repeat(60));
  console.log('DEPLOYMENT INSTRUCTIONS:');
  console.log('1. Create Render account at https://render.com');
  console.log('2. Create new Web Service');
  console.log('3. Connect your GitHub repository');
  console.log('4. Set environment variables:');
  console.log('   - CLIENT_ID: your_fanvue_client_id');
  console.log('   - CLIENT_SECRET: your_fanvue_client_secret');
  console.log('5. Set Redirect URI in Fanvue Dashboard to:');
  console.log('   https://your-app-name.onrender.com/oauth/callback');
  console.log('='.repeat(60));
});
