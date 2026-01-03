import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import fetch from "node-fetch";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

/** ===== ENV ===== **/
const {
  OAUTH_CLIENT_ID = "3c1182f1-ef24-49e7-a819-2814d97b8cd7",
  OAUTH_CLIENT_SECRET = "yT5DTwVWio4bVf7gca2gDuwbUS",
  OAUTH_REDIRECT_URI = "https://fanvue-proxy2.onrender.com/oauth/callback",
  OAUTH_SCOPES = "openid offline_access read:self read:fan read:insights",
  OAUTH_ISSUER_BASE_URL = "https://auth.fanvue.com",
  API_BASE_URL = "https://api.fanvue.com",
  SESSION_COOKIE_NAME = "mv_session",
  SESSION_SECRET = "x7gT$qL2!pK9@mN4",
  PORT = process.env.PORT || 3000
} = process.env;

/** ===== In-memory session store (MVP) ===== **/
const SESS = new Map(); // sid -> { access_token, refresh_token, expires_at, profile }

function sign(val) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}

function setSessionCookie(res, sid) {
  const sig = sign(sid);
  res.cookie(SESSION_COOKIE_NAME, `${sid}.${sig}`, {
    httpOnly: true,
    sameSite: "lax",
    secure: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: "/"
  });
}

function readSession(req) {
  const raw = req.cookies[SESSION_COOKIE_NAME];
  if (!raw) return null;
  const [sid, sig] = raw.split(".");
  if (!sid || !sig) return null;
  if (sign(sid) !== sig) return null;
  return SESS.get(sid) || null;
}

function clearSession(req, res) {
  const raw = req.cookies[SESSION_COOKIE_NAME];
  if (raw) {
    const [sid] = raw.split(".");
    if (sid) SESS.delete(sid);
  }
  res.clearCookie(SESSION_COOKIE_NAME, { path: "/", secure: true, sameSite: "lax" });
}

/** ===== OAuth Flow ===== **/
app.get("/oauth/start", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  const codeVerifier = crypto.randomBytes(32).toString("hex");
  
  // Store PKCE params temporarily (in-memory, expires in 10 mins)
  const tempStoreKey = `oauth_${state}`;
  SESS.set(tempStoreKey, { codeVerifier, timestamp: Date.now() });
  
  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");

  // CORRECT AUTHORIZATION URL (no spaces, proper endpoint)
  const authUrl = new URL(`${OAUTH_ISSUER_BASE_URL}/connect/authorize`);
  authUrl.searchParams.append("response_type", "code");
  authUrl.searchParams.append("client_id", OAUTH_CLIENT_ID);
  authUrl.searchParams.append("redirect_uri", OAUTH_REDIRECT_URI);
  authUrl.searchParams.append("scope", OAUTH_SCOPES);
  authUrl.searchParams.append("state", state);
  authUrl.searchParams.append("code_challenge", codeChallenge);
  authUrl.searchParams.append("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/oauth/callback", async (req, res) => {
  const { code, state } = req.query;
  
  if (!code || !state) {
    return res.status(400).send("Missing code or state");
  }

  // Retrieve PKCE params
  const tempStoreKey = `oauth_${state}`;
  const temp = SESS.get(tempStoreKey);
  if (!temp) {
    return res.status(400).send("Invalid or expired state");
  }
  SESS.delete(tempStoreKey);

  try {
    // Token exchange
    const basic = Buffer.from(`${OAUTH_CLIENT_ID}:${OAUTH_CLIENT_SECRET}`).toString("base64");
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: OAUTH_REDIRECT_URI,
      code_verifier: temp.codeVerifier
    });

    const tokenRes = await fetch(`${OAUTH_ISSUER_BASE_URL}/connect/token`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${basic}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body
    });

    if (!tokenRes.ok) {
      const error = await tokenRes.json().catch(() => ({}));
      console.error("Token exchange failed:", error);
      return res.status(400).send("Authentication failed");
    }

    const tokens = await tokenRes.json();
    
    // Get user profile - CORRECTED ENDPOINT
    const profileRes = await fetch(`${API_BASE_URL}/v1/me`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });

    if (!profileRes.ok) {
      const error = await profileRes.json().catch(() => ({}));
      console.error("Profile fetch failed:", error);
      return res.status(400).send("Failed to load profile");
    }

    const profile = await profileRes.json();
    
    // Create session
    const sid = crypto.randomBytes(24).toString("hex");
    SESS.set(sid, {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_at: Date.now() + tokens.expires_in * 1000,
      profile
    });
    
    setSessionCookie(res, sid);
    res.redirect("/");
  } catch (error) {
    console.error("OAuth callback error:", error);
    res.status(500).send("Internal server error");
  }
});

/** ===== API Endpoints ===== **/
app.get("/api/me", (req, res) => {
  const session = readSession(req);
  if (!session || !session.profile) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  
  // Return only necessary profile data
  res.json({
    username: session.profile.username || session.profile.name || "User",
    handle: `@${session.profile.username || "user"}`,
    avatar_url: session.profile.profile_image_url || session.profile.avatar_url || "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%234a4a6a' d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z'/%3E%3C/svg%3E",
    authenticated: true
  });
});

app.post("/api/logout", (req, res) => {
  clearSession(req, res);
  res.json({ status: "logged_out" });
});

/** ===== Session Cleanup ===== **/
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of SESS.entries()) {
    // Clean up expired temp OAuth stores
    if (key.startsWith("oauth_") && value.timestamp < now - 10 * 60 * 1000) {
      SESS.delete(key);
    }
    // Clean up expired sessions
    if (value.expires_at && value.expires_at < now) {
      SESS.delete(key);
    }
  }
}, 60 * 1000);

/** ===== Serve Frontend ===== **/
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

/** ===== Start Server ===== **/
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔑 OAuth Redirect URI: ${OAUTH_REDIRECT_URI}`);
});
