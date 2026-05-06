// server.cjs — Fanvue MVP + On My Time / DaniApp OAuth + Posting

require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");
const cookieParser = require("cookie-parser");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 10000;
const upload = multer({ storage: multer.memoryStorage() });

app.set("trust proxy", true);

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://thesuccessmindset.club");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Methods", "GET,POST,PATCH,PUT,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const CLIENT_ID = (process.env.CLIENT_ID || "").trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || "").trim();

const DANI_CLIENT_ID = (process.env.DANI_CLIENT_ID || "").trim();
const DANI_CLIENT_SECRET = (process.env.DANI_CLIENT_SECRET || "").trim();
const DANI_REDIRECT_URI = (process.env.DANI_REDIRECT_URI || "").trim();

const ADMIN_TOKEN = (process.env.ADMIN_TOKEN || "").trim();
const COOKIE_NAME = (process.env.SESSION_COOKIE_NAME || "fanvue_oauth").trim();
const SESSION_SECRET = (process.env.SESSION_SECRET || "change-me").trim();
const WEBHOOK_SECRET = (process.env.WEBHOOK_SECRET || "").trim();

const FANVUE_API_VERSION = "2025-06-26";

const oauthStates = new Map();
const sessions = new Map();
const webhookEvents = [];
const MAX_EVENTS = 100;

function rawBodySaver(req, res, buf) {
  if (buf && buf.length) req.rawBody = buf.toString("utf8");
}

app.use(express.json({ limit: "20mb", verify: rawBodySaver }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));
app.use(cookieParser(SESSION_SECRET));
app.use(express.static(path.join(__dirname, "public")));

function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return next();
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
    sameSite: "none",
    path: "/",
    maxAge: 1000 * 60 * 60 * 24 * 30,
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: "/" });
}

function addEvent(evt) {
  webhookEvents.unshift(evt);
  if (webhookEvents.length > MAX_EVENTS) webhookEvents.length = MAX_EVENTS;
}

function verifyFanvueSignature(req) {
  if (!WEBHOOK_SECRET) return { ok: true };

  const sig = (req.get("x-fanvue-signature") || "").trim();
  if (!sig) return { ok: false };

  const parts = Object.fromEntries(
    sig.split(",").map((kv) => {
      const [k, v] = kv.split("=");
      return [String(k || "").trim(), String(v || "").trim()];
    })
  );

  const t = parts.t;
  const v0 = parts.v0;

  if (!t || !v0) return { ok: false };

  const computed = crypto
    .createHmac("sha256", WEBHOOK_SECRET)
    .update(`${t}.${req.rawBody || ""}`, "utf8")
    .digest("hex");

  const a = Buffer.from(computed, "hex");
  const b = Buffer.from(v0, "hex");

  if (a.length !== b.length) return { ok: false };

  return { ok: crypto.timingSafeEqual(a, b) };
}

function normalizeWebhook(body) {
  const sender = body?.sender || {};

  return {
    type: body?.type || body?.event || "unknown",
    messageUuid: body?.messageUuid || body?.data?.id || body?.id || "",
    recipientUuid:
      body?.recipientUuid ||
      body?.recipient?.uuid ||
      body?.data?.recipientUuid ||
      "",
    senderName: sender?.displayName || sender?.handle || "",
    senderHandle: sender?.handle
      ? `@${String(sender.handle).replace(/^@/, "")}`
      : "",
    senderAvatar:
      sender?.avatarUri?.url ||
      sender?.avatarUriSm?.url ||
      sender?.avatarUriXs?.url ||
      "",
    text: body?.data?.text || body?.text || body?.message || "",
  };
}

function createPkceState() {
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

  return { state, nonce, codeVerifier, codeChallenge };
}

function getMediaType(mimetype) {
  if (mimetype.startsWith("video/")) return "video";
  if (mimetype.startsWith("audio/")) return "audio";
  if (mimetype.startsWith("image/")) return "image";
  return "document";
}

function extractCreatorProfile(creator) {
  return {
    name:
      creator.displayName ||
      creator.name ||
      creator.username ||
      creator.handle ||
      creator.email ||
      "Fanvue Creator",

    handle: creator.handle
      ? `@${String(creator.handle).replace(/^@/, "")}`
      : "",

    avatar:
      creator.avatarUrl ||
      creator.avatar_url ||
      creator.avatarUri?.url ||
      creator.avatarUriSm?.url ||
      creator.avatarUriXs?.url ||
      creator.profilePictureUrl ||
      creator.profile_picture_url ||
      creator.imageUrl ||
      creator.image_url ||
      "",
  };
}

function findSignedUrl(value) {
  if (!value) return "";

  if (typeof value === "string") {
    if (value.startsWith("https://")) return value;
    return "";
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findSignedUrl(item);
      if (found) return found;
    }
  }

  if (typeof value === "object") {
    const priorityKeys = [
      "url",
      "uploadUrl",
      "signedUrl",
      "presignedUrl",
      "href",
      "putUrl",
      "upload_url",
      "signed_url",
      "presigned_url",
    ];

    for (const key of priorityKeys) {
      const found = findSignedUrl(value[key]);
      if (found) return found;
    }

    for (const key of Object.keys(value)) {
      const found = findSignedUrl(value[key]);
      if (found) return found;
    }
  }

  return "";
}

console.log("=".repeat(60));
console.log("FANVUE MVP STARTING");
console.log("=".repeat(60));
console.log(`NODE_ENV: ${process.env.NODE_ENV || "development"}`);
console.log(`DANI_CLIENT_ID present: ${!!DANI_CLIENT_ID}`);
console.log(`DANI_CLIENT_SECRET present: ${!!DANI_CLIENT_SECRET}`);
console.log(`DANI_REDIRECT_URI present: ${!!DANI_REDIRECT_URI}`);
console.log(`PORT: ${PORT}`);
console.log("=".repeat(60));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/health", (req, res) => {
  res.status(200).send("ok");
});

app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET || !DANI_REDIRECT_URI) {
    return res
      .status(503)
      .send("Missing DANI_CLIENT_ID / DANI_CLIENT_SECRET / DANI_REDIRECT_URI.");
  }

  const pkce = createPkceState();

  const authUrl = new URL("https://auth.fanvue.com/oauth2/auth");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", DANI_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", DANI_REDIRECT_URI);
  authUrl.searchParams.set(
    "scope",
    "openid offline_access write:post write:media read:self"
  );
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("nonce", pkce.nonce);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  return res.redirect(authUrl.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res
      .status(400)
      .send(`Fanvue denied authorization: ${error} ${error_description || ""}`);
  }

  if (!code || !state) return res.status(400).send("Missing code/state");

  const st = oauthStates.get(state);
  if (!st) return res.status(400).send("Invalid/expired state.");

  oauthStates.delete(state);

  try {
    const basicAuth = Buffer.from(
      `${DANI_CLIENT_ID}:${DANI_CLIENT_SECRET}`
    ).toString("base64");

    const tokenResp = await axios.post(
      "https://auth.fanvue.com/oauth2/token",
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: DANI_REDIRECT_URI,
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
      "X-Fanvue-API-Version": FANVUE_API_VERSION,
    };

    let creator = {
      app: "On My Time",
      connected: true,
    };

    try {
      const profileResp = await axios.get("https://api.fanvue.com/users/me", {
        headers: apiHeaders,
        timeout: 20000,
      });

      creator = {
        ...creator,
        ...(profileResp.data || {}),
      };

      console.log("DANIAPP PROFILE:", creator);
    } catch (profileErr) {
      console.error(
        "DANIAPP PROFILE FETCH FAILED:",
        profileErr?.response?.status,
        profileErr?.response?.data || profileErr.message
      );
    }

    const profile = extractCreatorProfile(creator);
    const sid = crypto.randomBytes(24).toString("hex");

    sessions.set(sid, {
      accessToken,
      creator,
      ts: Date.now(),
    });

    setSessionCookie(res, sid);

    return res.redirect(
      "https://thesuccessmindset.club/daniapp/index.html" +
        "?connected=1" +
        "&name=" +
        encodeURIComponent(profile.name) +
        "&handle=" +
        encodeURIComponent(profile.handle) +
        "&avatar=" +
        encodeURIComponent(profile.avatar)
    );
  } catch (err) {
    console.error(
      "DANIAPP OAUTH FAILED:",
      err?.response?.status,
      err?.response?.data || err.message
    );

    return res.status(500).send("DaniApp OAuth failed. Check Render logs.");
  }
});

app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
  const s = getSession(req);

  if (!s || !s.accessToken) {
    return res.status(401).json({
      ok: false,
      error: "Fanvue is not connected. Reconnect Fanvue first.",
    });
  }

  if (!req.file) {
    return res.status(400).json({
      ok: false,
      error: "No media file uploaded.",
    });
  }

  const accessToken = s.accessToken;
  const caption = String(req.body.caption || "").trim();
  const audience = req.body.audience || "followers-and-subscribers";
  const postNow = req.body.postNow === "true";
  const scheduleTime = req.body.scheduleTime || "";
  const priceInput = Number(req.body.price || 0);

  if (!caption) {
    return res.status(400).json({ ok: false, error: "Caption is required." });
  }

  if (!["subscribers", "followers-and-subscribers"].includes(audience)) {
    return res.status(400).json({ ok: false, error: "Invalid audience." });
  }

  if (!postNow && !scheduleTime) {
    return res.status(400).json({
      ok: false,
      error: "Schedule time is required unless Post Now is selected.",
    });
  }

  try {
    const fanvueHeaders = {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION,
    };

    const uploadSession = await axios.post(
      "https://api.fanvue.com/media/uploads",
      {
        name: req.file.originalname,
        filename: req.file.originalname,
        mediaType: getMediaType(req.file.mimetype),
      },
      {
        headers: {
          ...fanvueHeaders,
          "Content-Type": "application/json",
        },
        timeout: 30000,
      }
    );

    const mediaUuid = uploadSession.data.mediaUuid;
    const uploadId = uploadSession.data.uploadId;

    if (!mediaUuid || !uploadId) {
      return res.status(500).json({
        ok: false,
        error: "Fanvue did not return mediaUuid/uploadId.",
        raw: uploadSession.data,
      });
    }

    const signedUrlResp = await axios.get(
      `https://api.fanvue.com/media/uploads/${encodeURIComponent(
        uploadId
      )}/parts/1/url`,
      {
        headers: fanvueHeaders,
        timeout: 30000,
      }
    );

    console.log("SIGNED URL RESPONSE:", JSON.stringify(signedUrlResp.data));

    const signedUrl = findSignedUrl(signedUrlResp.data);

    if (!signedUrl) {
      return res.status(500).json({
        ok: false,
        error: "Fanvue did not return a signed upload URL.",
        raw: signedUrlResp.data,
      });
    }

    const uploadPartResp = await axios.put(signedUrl, req.file.buffer, {
      headers: {
        "Content-Type": req.file.mimetype,
      },
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
      timeout: 120000,
      validateStatus: (status) => status >= 200 && status < 300,
    });

    const etagRaw =
      uploadPartResp.headers.etag || uploadPartResp.headers.ETag || "";

    const etag = String(etagRaw).replace(/^"|"$/g, "");

    const completePayload = etag
      ? {
          parts: [
            {
              ETag: etag,
              PartNumber: 1,
            },
          ],
        }
      : {
          parts: [
            {
              PartNumber: 1,
            },
          ],
        };

    const completeResp = await axios.patch(
      `https://api.fanvue.com/media/uploads/${encodeURIComponent(uploadId)}`,
      completePayload,
      {
        headers: {
          ...fanvueHeaders,
          "Content-Type": "application/json",
        },
        timeout: 30000,
      }
    );

    console.log("UPLOAD COMPLETE:", completeResp.data);

    await new Promise((resolve) => setTimeout(resolve, 8000));

    const postPayload = {
      text: caption,
      mediaUuids: [mediaUuid],
      audience: audience,
      visibility: "followers-and-subscribers",
      isArchived: false,
    };

    if (priceInput > 0) {
      postPayload.price = Math.round(priceInput * 100);
    }

    if (!postNow && scheduleTime) {
      postPayload.publishAt = new Date(scheduleTime).toISOString();
    }

    console.log("CREATE POST PAYLOAD:", postPayload);

    const postResp = await axios.post("https://api.fanvue.com/posts", postPayload, {
      headers: {
        ...fanvueHeaders,
        "Content-Type": "application/json",
      },
      timeout: 30000,
      validateStatus: (status) => status >= 200 && status < 300,
    });

    console.log("CREATE POST RESPONSE:", postResp.data);

    return res.json({
      ok: true,
      message: postNow ? "Post created." : "Post scheduled.",
      mediaUuid,
      uploadId,
      mediaStatus: completeResp.data,
      post: postResp.data,
    });
  } catch (err) {
    console.error(
      "DANIAPP POST FAILED:",
      err?.response?.status,
      err?.response?.data || err.message
    );

    return res.status(500).json({
      ok: false,
      error: "Fanvue post failed.",
      details: err?.response?.data || err.message,
    });
  }
});

app.get("/api/me", (req, res) => {
  const s = getSession(req);

  if (!s) return res.status(401).json({ error: "Not authenticated" });

  const profile = extractCreatorProfile(s.creator || {});

  return res.json({
    username: profile.name,
    handle: profile.handle,
    avatar_url: profile.avatar,
    raw: s.creator || {},
  });
});

app.post("/api/logout", (req, res) => {
  const sid = req.signedCookies?.[COOKIE_NAME];
  if (sid) sessions.delete(sid);
  clearSessionCookie(res);
  return res.json({ ok: true });
});

app.get("/webhooks/fanvue", (req, res) => {
  res.status(200).send("ok");
});

app.post("/webhooks/fanvue", (req, res) => {
  const ver = verifyFanvueSignature(req);

  if (!ver.ok) return res.status(401).send("invalid signature");

  const normalized = normalizeWebhook(req.body);

  addEvent({
    receivedAt: new Date().toISOString(),
    normalized,
    body: req.body,
  });

  return res.status(200).send("ok");
});

app.get("/api/events", (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: "Not authenticated" });

  return res.json({
    count: webhookEvents.length,
    events: webhookEvents,
  });
});

app.get("/api/events/last", (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: "Not authenticated" });

  return res.json(webhookEvents[0] || null);
});

app.post("/api/events/clear", requireAdmin, (req, res) => {
  webhookEvents.length = 0;
  return res.json({ ok: true });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.listen(PORT, () => {
  console.log("=".repeat(60));
  console.log("SERVER READY");
  console.log("=".repeat(60));
  console.log("Dani Start: https://fanvue-proxy2.onrender.com/daniapp/oauth/start");
  console.log("Dani Callback: https://fanvue-proxy2.onrender.com/daniapp/oauth/callback");
  console.log("Dani Post API: https://fanvue-proxy2.onrender.com/daniapp/api/post");
  console.log("=".repeat(60));
});
