// server.cjs — Fanvue MVP (OAuth + Profile in Dashboard + Webhooks + Dashboard Live View)

require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 10000;

app.set("trust proxy", true);

// --- ENV ---
const CLIENT_ID = (process.env.CLIENT_ID || "").trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || "").trim();
const ADMIN_TOKEN = (process.env.ADMIN_TOKEN || "").trim();

const COOKIE_NAME = (process.env.SESSION_COOKIE_NAME || "fanvue_oauth").trim();
const SESSION_SECRET = (process.env.SESSION_SECRET || "change-me").trim();

// Optional: webhook signature verification (if you set this, requests without valid sig will be rejected)
const WEBHOOK_SECRET = (process.env.WEBHOOK_SECRET || "").trim();

// --- In-memory stores (MVP) ---
const oauthStates = new Map(); // state -> { codeVerifier, nonce, ts }
const sessions = new Map(); // sid -> { accessToken, creator, ts }
const webhookEvents = []; // newest first
const MAX_EVENTS = 100;

// --- Raw-body capture for webhook signature verification ---
function rawBodySaver(req, res, buf) {
  if (buf && buf.length) req.rawBody = buf.toString("utf8");
}

// --- Middleware ---
app.use(
  express.json({
    limit: "2mb",
    verify: rawBodySaver,
  })
);
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(SESSION_SECRET));
app.use(express.static(path.join(__dirname, "public")));

// --- Helpers ---
function baseUrl(req) {
  return `https://${req.get("host")}`;
}

function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return next(); // admin auth disabled if token not set
  const got = (req.get("x-admin-token") || "").trim();
  if (got && got === ADMIN_TOKEN) return next();
  return res.status(401).json({ error: "Unauthorized" });
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
    sameSite: "lax",
    path: "/",
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: "/" });
}

function addEvent(evt) {
  webhookEvents.unshift(evt);
  if (webhookEvents.length > MAX_EVENTS) webhookEvents.length = MAX_EVENTS;
}

function safeJson(x) {
  try {
    return JSON.stringify(x, null, 2);
  } catch {
    return String(x);
  }
}

// --- OPTIONAL Fanvue signature verification ---
// NOTE: Fanvue’s exact signing format must match their docs.
// This implementation expects a header like: "t=...,v0=<hex-hmac>"
// and computes HMAC_SHA256(secret, `${t}.${rawBody}`).
function verifyFanvueSignature(req) {
  if (!WEBHOOK_SECRET) return { ok: true, reason: "WEBHOOK_SECRET not set (verification disabled)" };

  const sig = (req.get("x-fanvue-signature") || "").trim(); // ex: t=...,v0=...
  if (!sig) return { ok: false, reason: "missing x-fanvue-signature" };

  const parts = Object.fromEntries(
    sig.split(",").map((kv) => {
      const [k, v] = kv.split("=");
      return [String(k || "").trim(), String(v || "").trim()];
    })
  );

  const t = parts.t;
  const v0 = parts.v0;

  if (!t || !v0) return { ok: false, reason: "signature missing t or v0" };
  const raw = req.rawBody || "";

  const computed = crypto
    .createHmac("sha256", WEBHOOK_SECRET)
    .update(`${t}.${raw}`, "utf8")
    .digest("hex");

  // timing-safe compare
  const a = Buffer.from(computed, "hex");
  const b = Buffer.from(v0, "hex");
  if (a.length !== b.length) return { ok: false, reason: "signature length mismatch" };
  const ok = crypto.timingSafeEqual(a, b);
  return { ok, reason: ok ? "ok" : "signature mismatch" };
}

// Normalize Fanvue payloads to a consistent “display” object for the dashboard
function normalizeWebhook(body) {
  const sender = body?.sender || {};
  const senderName = sender?.displayName || sender?.handle || "";
  const senderHandle = sender?.handle ? `@${String(sender.handle).replace(/^@/, "")}` : "";

  const senderAvatar =
    sender?.avatarUri?.url ||
    sender?.avatarUriSm?.url ||
    sender?.avatarUriXs?.url ||
    "";

  const text =
    body?.data?.text ||
    body?.text ||
    body?.message ||
    "";

  const messageUuid = body?.messageUuid || body?.data?.id || body?.id || "";
  const recipientUuid = body?.recipientUuid || body?.recipient?.uuid || body?.data?.recipientUuid || "";

  // Fanvue may or may not include a "type"; your test payload didn’t.
  const type = body?.type || body?.event || "unknown";

  return {
    type,
    messageUuid,
    recipientUuid,
    senderName,
    senderHandle,
    senderAvatar,
    text,
  };
}

// --- Startup log ---
console.log("=".repeat(60));
console.log("FANVUE MVP STARTING");
console.log("=".repeat(60));
console.log(`NODE_ENV: ${process.env.NODE_ENV || "development"}`);
console.log(`CLIENT_ID present: ${!!CLIENT_ID}`);
console.log(`CLIENT_SECRET present: ${!!CLIENT_SECRET}`);
console.log(`ADMIN_TOKEN present: ${!!ADMIN_TOKEN}`);
console.log(`WEBHOOK_SECRET present: ${!!WEBHOOK_SECRET}`);
console.log(`PORT: ${PORT}`);
console.log("=".repeat(60));

// --- Routes ---

// Dashboard
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// Health
app.get("/health", (req, res) => res.status(200).send("ok"));

// OAuth start
app.get("/oauth/start", (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    return res.status(503).send("Missing CLIENT_ID / CLIENT_SECRET in environment.");
  }

  const state = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");

  const codeVerifier = crypto
    .randomBytes(32)
    .toString("base64url")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  oauthStates.set(state, { nonce, codeVerifier, ts: Date.now() });

  const redirectUri = `${baseUrl(req)}/oauth/callback`;

  const authUrl = new URL("https://auth.fanvue.com/oauth2/auth");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("scope", "openid offline_access read:self read:fan read:insights");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("nonce", nonce);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  return res.redirect(authUrl.toString());
});

// OAuth callback
app.get("/oauth/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state) return res.status(400).send("Missing code/state");

  const st = oauthStates.get(state);
  if (!st) return res.status(400).send("Invalid/expired state. Restart login.");
  oauthStates.delete(state);

  try {
    const redirectUri = `${baseUrl(req)}/oauth/callback`;
    const basicAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");

    const tokenResp = await axios.post(
      "https://auth.fanvue.com/oauth2/token",
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: st.codeVerifier,
      }).toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${basicAuth}`,
        },
        timeout: 20000,
      }
    );

    const accessToken = tokenResp.data.access_token;
    if (!accessToken) throw new Error("No access_token returned");

    const apiHeaders = {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": "2025-06-26",
    };

    const profileResp = await axios.get("https://api.fanvue.com/users/me", {
      headers: apiHeaders,
      timeout: 20000,
    });

    const creator = profileResp.data || {};

    // session
    const sid = crypto.randomBytes(24).toString("hex");
    sessions.set(sid, { accessToken, creator, ts: Date.now() });
    setSessionCookie(res, sid);

    // redirect back to dashboard (mobile-friendly)
    return res.redirect("/");
  } catch (err) {
    const status = err?.response?.status;
    const data = err?.response?.data;
    console.error("OAuth callback failed:", status, data || err.message);
    return res.status(500).send("Authentication failed. Check Render logs.");
  }
});

// API: me (dashboard uses this)
app.get("/api/me", (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: "Not authenticated" });

  const c = s.creator || {};
  return res.json({
    username: c.displayName || c.handle || "Creator",
    handle: c.handle ? `@${String(c.handle).replace(/^@/, "")}` : "",
    avatar_url: c.avatarUrl || "",
    raw: c,
  });
});

// API: logout
app.post("/api/logout", (req, res) => {
  const sid = req.signedCookies?.[COOKIE_NAME];
  if (sid) sessions.delete(sid);
  clearSessionCookie(res);
  return res.json({ ok: true });
});

// --- Webhooks ---
// Fanvue will POST here. Browsers often GET it; we return ok for GET.
app.get("/webhooks/fanvue", (req, res) => res.status(200).send("ok"));

app.post("/webhooks/fanvue", (req, res) => {
  // optional signature verification
  const ver = verifyFanvueSignature(req);
  if (!ver.ok) {
    console.warn("❌ Webhook rejected:", ver.reason);
    return res.status(401).send("invalid signature");
  }

  const receivedAt = new Date().toISOString();
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";

  const normalized = normalizeWebhook(req.body);

  const evt = {
    receivedAt,
    ip,
    headers: {
      "user-agent": req.headers["user-agent"],
      "content-type": req.headers["content-type"],
      "x-fanvue-signature": req.headers["x-fanvue-signature"],
      "x-fanvue-timestamp": req.headers["x-fanvue-timestamp"],
    },
    normalized,
    body: req.body,
  };

  addEvent(evt);

  console.log("✅ Fanvue webhook received:", {
    type: normalized.type,
    messageUuid: normalized.messageUuid,
    sender: normalized.senderHandle || normalized.senderName,
  });

  return res.status(200).send("ok");
});

// API: events (dashboard)
app.get("/api/events", (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: "Not authenticated" });
  return res.json({ count: webhookEvents.length, events: webhookEvents });
});

// API: last (dashboard)
app.get("/api/events/last", (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: "Not authenticated" });
  return res.json(webhookEvents[0] || null);
});

// Optional: clear events (admin)
app.post("/api/events/clear", requireAdmin, (req, res) => {
  webhookEvents.length = 0;
  return res.json({ ok: true });
});

// SPA fallback -> dashboard
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.listen(PORT, () => {
  console.log("=".repeat(60));
  console.log("SERVER READY");
  console.log("=".repeat(60));
  console.log("Dashboard:  https://fanvue-proxy2.onrender.com/");
  console.log("OAuth Start: https://fanvue-proxy2.onrender.com/oauth/start");
  console.log("Callback:    https://fanvue-proxy2.onrender.com/oauth/callback");
  console.log("Webhook:     https://fanvue-proxy2.onrender.com/webhooks/fanvue");
  console.log("Events:      https://fanvue-proxy2.onrender.com/api/events");
  console.log("Last Event:  https://fanvue-proxy2.onrender.com/api/events/last");
  console.log("=".repeat(60));
});
