require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;

// Trust Render's proxy headers
app.set('trust proxy', true);

// TRIM ENVIRONMENT VARIABLES (CRITICAL FIX)
const CLIENT_ID = (process.env.CLIENT_ID || '').trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || '').trim();

console.log('='.repeat(60));
console.log('ENVIRONMENT DEBUG');
console.log('='.repeat(60));
console.log(`CLIENT_ID length: ${CLIENT_ID.length}`);
console.log(`CLIENT_SECRET length: ${CLIENT_SECRET.length}`);
console.log(`Using Node version: ${process.version}`);
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
  console.log('AUTHORIZATION REQUEST');
  console.log('='.repeat(60));
  console.log(`Host header: ${req.get('host')}`);
  console.log(`Protocol: ${req.protocol}`);
  console.log(`Redirect URI: [${redirectUri}]`);
  console.log(`Redirect URI length: ${redirectUri.length}`);
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
    // DYNAMIC REDIRECT URI WITH TRIMMING
    const redirectUri = `${req.protocol}://${req.get('host')}/oauth/callback`.trim();

    console.log('='.repeat(60));
    console.log('TOKEN EXCHANGE ATTEMPT');
    console.log('='.repeat(60));
    console.log(`Redirect URI: [${redirectUri}]`);
    console.log(`Client ID: ${CLIENT_ID}`);
    console.log(`Client Secret length: ${CLIENT_SECRET.length}`);
    
    // DEBUG: Show Basic Auth header format
    const basicAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    console.log(`Basic Auth header: Basic ${basicAuth.substring(0, 15)}...${basicAuth.substring(basicAuth.length - 4)}`);
    console.log('='.repeat(60));

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
        timeout: 30000
      }
    );

    const accessToken = tokenResponse.data.access_token;
    console.log('✅ Token exchange successful');

    const apiHeaders = {
      Authorization: `Bearer ${accessToken}`,
      'X-Fanvue-API-Version': '2025-06-26',
    };

    const profileResponse = await axios.get('https://api.fanvue.com/users/me', {
      headers: apiHeaders,
    });

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
          .raw { margin: 40px; background: #1e1e1e; color: #f8f8f2; padding: 20px; border-radius: 12px; overflow-x: auto; font-family: 'Courier New', monospace; }
          a { color: #667eea; font-weight: bold; text-decoration: none; }
          footer { text-align: center; padding: 30px; color: #888; font-size: 0.9em; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>✅ Fanvue API Connected Successfully!</h1>
            <p>Your authentication flow is now working on Render.</p>
          </div>

          <div class="profile-section">
            ${profilePic 
              ? `<img src="${profilePic}" alt="${creatorName}'s Profile Picture">`
              : `<div class="no-photo">No Photo</div>`
            }
            <div class="info">
              <h1>${creatorName}</h1>
              <p>Render Deployment Successful</p>
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
Render URL: https://fanvue-proxy2.onrender.com
Redirect URI used: ${redirectUri}
Client ID length: ${CLIENT_ID.length}
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
    console.error('🔥 AUTHENTICATION FAILED - CRITICAL DEBUG INFO');
    console.error('='.repeat(60));
    
    if (error.response) {
      console.error('❌ HTTP Status:', error.response.status);
      console.error('❌ Error Response:', JSON.stringify(error.response.data, null, 2));
      
      // SPECIAL DEBUG FOR INVALID_CLIENT
      if (error.response.data.error === 'invalid_client') {
        console.error('='.repeat(60));
        console.error('🚨 INVALID_CLIENT ERROR - CHECK THESE ITEMS:');
        console.error('='.repeat(60));
        console.error('1. REDIRECT URI MISMATCH:');
        console.error(`   Current URI: https://${req.get('host')}/oauth/callback`);
        console.error('   Must be EXACTLY: https://fanvue-proxy2.onrender.com/oauth/callback');
        console.error('');
        console.error('2. CLIENT CREDENTIALS:');
        console.error(`   Client ID length: ${CLIENT_ID.length} characters`);
        console.error(`   Client Secret length: ${CLIENT_SECRET.length} characters`);
        console.error('   Check for whitespace in environment variables!');
        console.error('');
        console.error('3. FANVUE DASHBOARD CONFIGURATION:');
        console.error('   Go to https://developers.fanvue.com');
        console.error('   Verify Redirect URI is EXACTLY:');
        console.error('   https://fanvue-proxy2.onrender.com/oauth/callback');
        console.error('='.repeat(60));
      }
    } else {
      console.error('❌ Network Error:', error.message);
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
            <p><strong>Render URL:</strong> https://fanvue-proxy2.onrender.com</p>
            <p><strong>Redirect URI being used:</strong> <code>https://${req.get('host')}/oauth/callback</code></p>
            <p><strong>Client ID length:</strong> ${CLIENT_ID.length} characters</p>
          </div>

          <div class="fix-steps">
            <h2>✅ Required Fixes</h2>
            <ol>
              <li><strong>Update Fanvue Developer Dashboard:</strong><br>
              Set Redirect URI to EXACTLY:<br>
              <code>https://fanvue-proxy2.onrender.com/oauth/callback</code></li>
              
              <li><strong>Verify Render Environment Variables:</strong><br>
              In Render dashboard, check for whitespace in:<br>
              <code>CLIENT_ID</code> and <code>CLIENT_SECRET</code></li>
              
              <li><strong>Clear Browser Cookies:</strong><br>
              Clear cookies for <code>fanvue-proxy2.onrender.com</code> before retrying</li>
            </ol>
          </div>

          <div class="debug">
            <h2>📋 Full Error Details</h2>
            <pre>${JSON.stringify(error.response?.data || {message: error.message}, null, 2)}</pre>
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

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/*anything', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('🚀 FANVUE SERVER READY FOR RENDER');
  console.log('='.repeat(60));
  console.log(`Server running on port ${PORT}`);
  console.log(`✅ CORRECT REDIRECT URI FOR FANVUE DASHBOARD:`);
  console.log(`https://fanvue-proxy2.onrender.com/oauth/callback`);
  console.log('='.repeat(60));
  console.log('🔧 DEPLOYMENT CHECKLIST:');
  console.log('1. Set environment variables in Render dashboard (no whitespace!)');
  console.log('2. Update Fanvue Redirect URI to EXACT URL above');
  console.log('3. Clear browser cookies before testing');
  console.log('='.repeat(60));
});
