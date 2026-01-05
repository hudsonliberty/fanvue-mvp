// server.cjs - Production Fanvue OAuth Server (Render)

// env
require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 10000;

// Trust proxy for Render
app.set("trust proxy", true);

// ENV
const CLIENT_ID = (process.env.CLIENT_ID || "").trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || "").trim();
const SESSION_COOKIE_NAME = (process.env.SESSION_COOKIE_NAME || "fanvue_oauth").trim();
const SESSION_SECRET = (process.env.SESSION_SECRET || "change_me").trim();

// Fanvue constants (your current working endpoints)
const FANVUE_AUTH_URL = "https://auth.fanvue.com/oauth2/auth";
const FANVUE_TOKEN_URL = "https://auth.fanvue.com/oauth2/token";
const FANVUE_API_ME_URL = "https://api.fanvue.com/users/me";
const FANVUE_API_SUBSCRIBERS_URL = "https://api.fanvue.com/subscribers";
const FANVUE_API_VERSION = "2025-06-26";

console.log("=".repeat(60));
console.log("FANVUE SERVER STARTING");
console.log("=".repeat(60));
console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
console.log(`Client ID present: ${!!CLIENT_ID}`);
console.log(`Client Secret present: ${!!CLIENT_SECRET}`);
console.log(`Port: ${PORT}`);
console.log("=".repeat(60));

// ---- session stores ----
// sid -> session data (tokens, creator, etc.)
const sessionsBySid = new Map();
// state -> sid (for callback validation)
const stateToSid = new Map();

function signSid(sid) {
  const mac = crypto.createHmac("sha256", SESSION_SECRET).update(sid).digest("hex");
  return `${sid}.${mac}`;
}

function verifySignedSid(signed) {
  if (!signed || typeof signed !== "string") return null;
  const [sid, mac] = signed.split(".");
  if (!sid || !mac) return null;
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(sid).digest("hex");
  if (crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return sid;
  return null;
}

function setSessionCookie(res, sid) {
  // Render is HTTPS, so secure cookie works
  res.cookie(SESSION_COOKIE_NAME, signSid(sid), {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
  });
}

function clearSession(res) {
  res.clearCookie(SESSION_COOKIE_NAME, { path: "/" });
}

function getSid(req) {
  const signed = req.cookies?.[SESSION_COOKIE_NAME];
  return verifySignedSid(signed);
}

function getRedirectUri(req) {
  // IMPORTANT: Fanvue app must whitelist exactly this
  return `https://${req.get("host")}/oauth/callback`;
}

// ---- middleware ----
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// CORS preflight (keep)
app.options("/*anything", (req, res) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.sendStatus(200);
});

// ---- UI ----
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// ---- API: who am I (for dashboard avatar/name) ----
app.get("/api/me", async (req, res) => {
  try {
    const sid = getSid(req);
    if (!sid) return res.status(401).json({ error: "Not authenticated" });

    const sess = sessionsBySid.get(sid);
    if (!sess?.accessToken) return res.status(401).json({ error: "Not authenticated" });

    // If we already cached creator, return fast
    if (sess.creator) {
      return res.json({
        username: sess.creator.displayName || sess.creator.handle || "Creator",
        handle: sess.creator.handle ? `@${sess.creator.handle}` : "",
        avatar_url: sess.creator.avatarUrl || ""
      });
    }

    // Otherwise fetch
    const apiHeaders = {
      Authorization: `Bearer ${sess.accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION
    };

    const profileResponse = await axios.get(FANVUE_API_ME_URL, { headers: apiHeaders });
    const creator = profileResponse.data;

    sess.creator = creator;
    sessionsBySid.set(sid, sess);

    return res.json({
      username: creator.displayName || creator.handle || "Creator",
      handle: creator.handle ? `@${creator.handle}` : "",
      avatar_url: creator.avatarUrl || ""
    });
  } catch (e) {
    return res.status(401).json({ error: "Not authenticated" });
  }
});

app.post("/api/logout", (req, res) => {
  const sid = getSid(req);
  if (sid) sessionsBySid.delete(sid);
  clearSession(res);
  res.json({ ok: true });
});

// Optional: quick dashboard stat endpoint
app.get("/api/stats", async (req, res) => {
  try {
    const sid = getSid(req);
    if (!sid) return res.status(401).json({ error: "Not authenticated" });

    const sess = sessionsBySid.get(sid);
    if (!sess?.accessToken) return res.status(401).json({ error: "Not authenticated" });

    const apiHeaders = {
      Authorization: `Bearer ${sess.accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION
    };

    const [profileResponse, subscribersResponse] = await Promise.all([
      axios.get(FANVUE_API_ME_URL, { headers: apiHeaders }),
      axios.get(FANVUE_API_SUBSCRIBERS_URL, { params: { page: 1, size: 50 }, headers: apiHeaders })
    ]);

    const creator = profileResponse.data;
    const subscribers = subscribersResponse.data?.data || [];

    // cache creator
    sess.creator = creator;
    sessionsBySid.set(sid, sess);

    res.json({
      followersCount: creator.fanCounts?.followersCount || 0,
      subscribersCount: creator.fanCounts?.subscribersCount || 0,
      subscribersShown: subscribers.length
    });
  } catch (e) {
    res.status(500).json({ error: "stats_failed" });
  }
});

// ---- WEBHOOKS ----
app.post("/webhooks/fanvue", (req, res) => {
  // Fanvue will POST here. GET will still show "Cannot GET" and that's OK.
  console.log("✅ Fanvue webhook received:", req.headers, req.body);
  res.status(200).send("ok");
});

// ---- OAUTH ----
if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error("Missing CLIENT_ID or CLIENT_SECRET – OAuth routes disabled");
  app.get("/oauth/start", (req, res) => {
    res.status(503).send(`
      <h1>Server Misconfigured</h1>
      <p>Set <code>CLIENT_ID</code> and <code>CLIENT_SECRET</code> in Render env vars.</p>
      <p>Callback must be exactly:</p>
      <code>${getRedirectUri(req)}</code>
    `);
  });
} else {
  app.get("/oauth/start", (req, res) => {
    // create sid cookie
    const sid = crypto.randomBytes(16).toString("hex");
    setSessionCookie(res, sid);

    const state = crypto.randomBytes(16).toString("hex");
    const nonce = crypto.randomBytes(16).toString("hex");

    const codeVerifier = crypto.randomBytes(32).toString("base64url")
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

    const codeChallenge = crypto.createHash("sha256")
      .update(codeVerifier)
      .digest("base64url")
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

    // store session by sid, map state->sid
    sessionsBySid.set(sid, { nonce, codeVerifier, timestamp: Date.now() });
    stateToSid.set(state, sid);

    const redirectUri = getRedirectUri(req);

    console.log("=".repeat(60));
    console.log("AUTHORIZATION REQUEST");
    console.log(`Redirect URI used: ${redirectUri}`);
    console.log("=".repeat(60));

    const authUrl = new URL(FANVUE_AUTH_URL);
    authUrl.searchParams.append("response_type", "code");
    authUrl.searchParams.append("client_id", CLIENT_ID);
    authUrl.searchParams.append("redirect_uri", redirectUri);
    authUrl.searchParams.append("scope", "openid offline_access read:self read:fan read:insights");
    authUrl.searchParams.append("state", state);
    authUrl.searchParams.append("nonce", nonce);
    authUrl.searchParams.append("code_challenge", codeChallenge);
    authUrl.searchParams.append("code_challenge_method", "S256");

    res.redirect(authUrl.toString());
  });
}

app.get("/oauth/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state) {
    return res.status(400).send(`
      <h1>Missing code or state</h1>
      <a href="/oauth/start">← Retry Login</a>
    `);
  }

  const sid = getSid(req);
  if (!sid) {
    return res.status(400).send(`
      <h1>Missing session cookie</h1>
      <p>Start login again.</p>
      <a href="/oauth/start">← Retry Login</a>
    `);
  }

  const expectedSid = stateToSid.get(state);
  if (!expectedSid || expectedSid !== sid) {
    return res.status(400).send(`
      <h1>Invalid or expired state</h1>
      <a href="/oauth/start">← Retry Login</a>
    `);
  }

  const sess = sessionsBySid.get(sid);
  if (!sess) {
    return res.status(400).send(`
      <h1>Session expired</h1>
      <a href="/oauth/start">← Retry Login</a>
    `);
  }

  // consume state mapping
  stateToSid.delete(state);

  try {
    const redirectUri = getRedirectUri(req);
    const basicAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");

    console.log("=".repeat(60));
    console.log("TOKEN EXCHANGE");
    console.log(`Redirect URI: ${redirectUri}`);
    console.log("=".repeat(60));

    const tokenResponse = await axios.post(
      FANVUE_TOKEN_URL,
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: sess.codeVerifier
      }).toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${basicAuth}`
        }
      }
    );

    const accessToken = tokenResponse.data.access_token;
    const refreshToken = tokenResponse.data.refresh_token;

    sess.accessToken = accessToken;
    sess.refreshToken = refreshToken;
    sess.tokenAt = Date.now();
    sessionsBySid.set(sid, sess);

    // fetch + cache creator once so dashboard shows immediately
    const apiHeaders = {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION
    };
    const profileResponse = await axios.get(FANVUE_API_ME_URL, { headers: apiHeaders });
    sess.creator = profileResponse.data;
    sessionsBySid.set(sid, sess);

    // send user back to dashboard (not a separate success page)
    return res.redirect("/?connected=1");
  } catch (error) {
    console.error("AUTHENTICATION FAILED");
    if (error.response) {
      console.error("Status:", error.response.status);
      console.error("Data:", JSON.stringify(error.response.data, null, 2));
    } else {
      console.error(error.message);
    }

    const errorMsg = error.response?.data?.error_description || error.message || "Unknown error";

    return res.status(500).send(`
      <h1>Authentication Failed</h1>
      <p><strong>Error:</strong> ${errorMsg}</p>
      <p><a href="/oauth/start">← Retry Login</a></p>
    `);
  }
});

// ---- SPA fallback MUST be last (after oauth/api/webhooks) ----
app.get("/*anything", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.listen(PORT, () => {
  console.log("=".repeat(60));
  console.log("SERVER READY");
  console.log("=".repeat(60));
  console.log(`Dashboard: https://fanvue-proxy2.onrender.com`);
  console.log(`Start OAuth: https://fanvue-proxy2.onrender.com/oauth/start`);
  console.log(`Expected Redirect URI: https://fanvue-proxy2.onrender.com/oauth/callback`);
  console.log("Webhook POST: https://fanvue-proxy2.onrender.com/webhooks/fanvue`);
  console.log("=".repeat(60));
});
