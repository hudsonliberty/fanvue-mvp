require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;

// Trust Render's proxy headers
app.set('trust proxy', true);

// TRIM ENVIRONMENT VARIABLES (CRITICAL)
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

  // DYNAMIC REDIRECT URI WITH TRIMMING
  const redirectUri = `${req.protocol}://${req.get('host')}/oauth/callback`.trim();

  console.log('='.repeat(60));
  console.log('🔗 AUTHORIZATION REQUEST');
  console.log('='.repeat(60));
  console.log(`Host: ${req.get('host')}`);
  console.log(`Protocol: ${req.protocol}`);
  console.log(`Redirect URI: [${redirectUri}]`);
  console.log(`URI length: ${redirectUri.length}`);
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
    console.error('❌ Missing code or state parameter');
    return res.status(400).send('<h1>Missing code or state</h1><a href="/oauth/start">Retry</a>');
  }

  const session = sessions.get(state);
  if (!session) {
    console.error('❌ Session not found for state:', state);
    return res.status(400).send('<h1>Invalid or expired state</h1><a href="/oauth/start">Restart</a>');
  }

  sessions.delete(state);

  try {
    // DYNAMIC REDIRECT URI WITH TRIMMING
    const redirectUri = `${req.protocol}://${req.get('host')}/oauth/callback`.trim();

    console.log('='.repeat(60));
    console.log('🔑 TOKEN EXCHANGE ATTEMPT');
    console.log('='.repeat(60));
    console.log(`Redirect URI: [${redirectUri}]`);
    console.log(`Client ID: ${CLIENT_ID.substring(0, 8)}...${CLIENT_ID.substring(CLIENT_ID.length - 4)}`);
    console.log(`Client Secret length: ${CLIENT_SECRET.length}`);
    
    // CORRECT BASIC AUTH FORMATTING
    const basicAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    console.log(`Basic Auth header: Basic ${basicAuth.substring(0, 10)}...${basicAuth.substring(basicAuth.length - 4)}`);
    
    // DEBUG: Show exact request data
    const requestData = {
      grant_type: 'authorization_code',
      code: code.substring(0, 10) + '...',
      redirect_uri: redirectUri,
      code_verifier: session.codeVerifier.substring(0, 10) + '...'
    };
    console.log('Request data:', requestData);
    console.log('='.repeat(60));

    // CORRECTED REQUEST WITH ALL REQUIRED HEADERS
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
          'User-Agent': 'Fanvue-API-Client/1.0'
        },
        timeout: 30000
      }
    );

    console.log('✅ Token exchange successful');
    console.log('Access Token (first 20 chars):', tokenResponse.data.access_token.substring(0, 20) + '...');

    const apiHeaders = {
      'Authorization': `Bearer ${tokenResponse.data.access_token}`,
      'X-Fanvue-API-Version': '2025-06-26',
      'Accept': 'application/json',
      'User-Agent': 'Fanvue-API-Client/1.0'
    };

    console.log('='.repeat(60));
    console.log('👤 FETCHING CREATOR PROFILE');
    console.log('='.repeat(60));
    
    const profileResponse = await axios.get('https://api.fanvue.com/users/me', {
      headers: apiHeaders,
    });

    const creatorData = profileResponse.data || {};
    const creatorName = creatorData.displayName || creatorData.handle || 'Unknown Creator';
    const profilePic = creatorData.avatarUrl || '';

    console.log(`✅ Creator Name: ${creatorName}`);
    console.log(`✅ Profile Picture URL: ${profilePic ? profilePic.substring(0, 30) + '...' : 'Not found'}`);

    console.log('='.repeat(60));
    console.log('👥 FETCHING SUBSCRIBERS');
    console.log('='.repeat(60));
    
    const subscribersResponse = await axios.get('https://api.fanvue.com/v1/creator/subscribers', {
      params: { page: 1, size: 50 },
      headers: apiHeaders,
    });

    const subscribers = subscribersResponse.data.data || [];
    console.log(`✅ Found ${subscribers.length} subscribers`);

    // SUCCESS PAGE
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
            <h1>✅ Fanvue API Connected Successfully!</h1>
            <p>Authentication completed on Render deployment</p>
          </div>

          <div class="profile-section">
            ${profilePic 
              ? `<img src="${profilePic}" alt="${creatorName}'s Profile Picture">`
              : `<div class="no-photo">No Photo</div>`
            }
            <div class="info">
              <h1>${creatorName}</h1>
              <p>Render Deployment Working</p>
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
            <h3>Debug Information</h3>
            <pre>
Server: https://fanvue-proxy2.onrender.com
Node Version: ${process.version}
Client ID: ${CLIENT_ID.substring(0, 8)}...${CLIENT_ID.substring(CLIENT_ID.length - 4)}
            </pre>
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
    console.error('🔥 AUTHENTICATION FAILED');
    console.error('='.repeat(60));
    
    if (error.response) {
      console.error('❌ HTTP Status:', error.response.status);
      console.error('❌ Headers:', JSON.stringify(error.response.headers, null, 2));
      console.error('❌ Response Data:', JSON.stringify(error.response.data, null, 2));
      
      if (error.response.data.error === 'invalid_client') {
        console.error('='.repeat(60));
        console.error('🚨 CRITICAL INVALID_CLIENT ERROR');
        console.error('='.repeat(60));
        console.error('Most likely causes:');
        console.error('1. Client ID/Secret mismatch in Render environment variables');
        console.error('2. Redirect URI mismatch in Fanvue Developer Dashboard');
        console.error('3. Extra whitespace in credentials');
        console.error('');
        console.error('✅ REQUIRED FIXES:');
        console.error('1. In Render Dashboard, verify environment variables EXACTLY:');
        console.error('   CLIENT_ID=3c1182f1-ef24-49e7-a819-2814d97b8cd7');
        console.error('   CLIENT_SECRET=67b0174157d0faa5b51a5442556f66493e2d8f55e45c68c29e32c64a0162ba0d');
        console.error('2. In Fanvue Dashboard, set Redirect URI EXACTLY to:');
        console.error('   https://fanvue-proxy2.onrender.com/oauth/callback');
        console.error('='.repeat(60));
      }
    } else if (error.request) {
      console.error('❌ No response received - network error');
      console.error('❌ Request config:', JSON.stringify(error.config, null, 2));
    } else {
      console.error('❌ Error details:', error.message);
    }

    res.status(500).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Authentication Failed</title>
        <style>
          body { font-family: Arial, sans-serif; background: #f8f9fa; padding: 40px; color: #333; }
          .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 16px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
          .error { background: #f8d7da; color: #721c24; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
          .debug { background: #e9ecef; padding: 25px; border-radius: 12px; margin: 25px 0; font-family: monospace; }
          .fix-steps { background: #d1ecf1; color: #0c5460; padding: 25px; border-radius: 12px; margin: 25px 0; }
          pre { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 8px; overflow-x: auto; }
          a { color: #007bff; font-weight: bold; text-decoration: none; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="error">
            <h1>❌ Authentication Failed</h1>
            <p><strong>Error:</strong> ${error.response?.data?.error_description || error.message}</p>
          </div>

          <div class="debug">
            <h2>🔍 Current Configuration</h2>
            <p><strong>Server URL:</strong> https://fanvue-proxy2.onrender.com</p>
            <p><strong>Redirect URI:</strong> <code>https://${req.get('host')}/oauth/callback</code></p>
            <p><strong>Client ID length:</strong> ${CLIENT_ID.length} characters</p>
          </div>

          <div class="fix-steps">
            <h2>✅ Required Fixes</h2>
            <ol>
              <li><strong>Update Fanvue Developer Dashboard:</strong><br>
              Set Redirect URI to EXACTLY:<br>
              <code>https://fanvue-proxy2.onrender.com/oauth/callback</code></li>
              
              <li><strong>Verify Render Environment Variables:</strong><br>
              In Render dashboard, check these EXACT values:<br>
              <code>CLIENT_ID=3c1182f1-ef24-49e7-a819-2814d97b8cd7</code><br>
              <code>CLIENT_SECRET=67b0174157d0faa5b51a5442556f66493e2d8f55e45c68c29e32c64a0162ba0d</code></li>
              
              <li><strong>Clear Browser Cookies:</strong><br>
              Clear cookies for <code>fanvue-proxy2.onrender.com</code> before retrying</li>
            </ol>
          </div>

          <p style="text-align: center; margin-top: 30px;">
            <a href="/oauth/start" style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">
              Retry Authentication
            </a>
          </p>
        </div>
      </body>
      </html>
    `);
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/*anything', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('✅ FANVUE SERVER READY');
  console.log('='.repeat(60));
  console.log(`Server running on port ${PORT}`);
  console.log(`✅ Production URL: https://fanvue-proxy2.onrender.com`);
  console.log(`✅ OAuth URL: https://fanvue-proxy2.onrender.com/oauth/start`);
  console.log(`✅ CORRECT Redirect URI for Fanvue Dashboard:`);
  console.log(`https://fanvue-proxy2.onrender.com/oauth/callback`);
  console.log('='.repeat(60));
  console.log('🔧 REMEMBER TO:');
  console.log('1. Set environment variables in Render dashboard EXACTLY as shown above');
  console.log('2. Update Fanvue Developer Dashboard with the exact Redirect URI');
  console.log('3. Clear browser cookies before testing');
  console.log('='.repeat(60));
});
