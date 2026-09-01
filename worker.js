/**
 * Weeksolved — outgoing mail service.
 *
 * A single Cloudflare Worker. The app posts a message here with the signed-in
 * manager's Firebase token; this checks the token is genuine, keeps the account
 * inside a daily limit, and hands the message to Resend to deliver.
 *
 * Nothing about a schedule passes through here beyond the words the manager
 * already wrote and read. No message is stored.
 *
 * Deploy:
 *   npm create cloudflare@latest weeksolved-mail
 *   (replace src/index.js with this file, and wrangler.toml with the one beside it)
 *   npx wrangler secret put RESEND_KEY
 *   npx wrangler deploy
 */

const DAILY_CAP = 500;          // per account, per day — a very long way above real use
const MAX_RECIPIENTS = 60;      // one send
const MAX_BODY = 20000;

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get("Origin") || "";
    const cors = corsHeaders(origin, env);

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (request.method !== "POST")   return json({ ok: false, error: "post only" }, 405, cors);

    const url = new URL(request.url);
    if (url.pathname !== "/send") return json({ ok: false, error: "not found" }, 404, cors);

    // ---- who is asking? ----
    const auth = request.headers.get("Authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!token) return json({ ok: false, error: "not signed in" }, 401, cors);

    let claims;
    try {
      claims = await verifyFirebaseToken(token, env.FIREBASE_PROJECT_ID);
    } catch (e) {
      return json({ ok: false, error: "that sign-in didn't check out" }, 401, cors);
    }
    const uid = claims.user_id || claims.sub;
    if (!uid) return json({ ok: false, error: "that sign-in didn't check out" }, 401, cors);

    // ---- what are they sending? ----
    let body;
    try { body = await request.json(); } catch (e) { return json({ ok: false, error: "unreadable request" }, 400, cors); }

    const to = (Array.isArray(body.to) ? body.to : [])
      .map(x => String(x || "").trim())
      .filter(x => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(x))
      .slice(0, MAX_RECIPIENTS);
    const subject = String(body.subject || "").slice(0, 200).replace(/[\r\n]/g, " ");
    const text = String(body.text || "").slice(0, MAX_BODY);
    const fromName = String(body.fromName || "Weeksolved").slice(0, 60).replace(/[\r\n"<>]/g, "");
    const replyTo = String(body.replyTo || "").trim().slice(0, 200);

    if (!to.length) return json({ ok: false, error: "no valid email addresses" }, 400, cors);
    if (!text)      return json({ ok: false, error: "nothing to send" }, 400, cors);

    // ---- a daily ceiling per account, so a bug or a bad actor can't run up a bill ----
    const key = "cap:" + uid + ":" + new Date().toISOString().slice(0, 10);
    let used = 0;
    if (env.MAILKV) {
      used = parseInt((await env.MAILKV.get(key)) || "0", 10) || 0;
      if (used + to.length > DAILY_CAP) {
        return json({ ok: false, error: "that account has reached today's sending limit" }, 429, cors);
      }
    }

    // ---- hand it to the sender ----
    const payload = {
      from: `${fromName} <${env.MAIL_FROM}>`,
      to,
      subject: subject || "A note about your schedule",
      text
    };
    if (replyTo && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(replyTo)) payload.reply_to = replyTo;

    let res, out;
    try {
      res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + env.RESEND_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      });
      out = await res.json().catch(() => ({}));
    } catch (e) {
      return json({ ok: false, error: "the mail service didn't answer" }, 502, cors);
    }

    if (!res.ok) {
      const why = (out && (out.message || out.name)) || ("the mail service answered " + res.status);
      return json({ ok: false, error: String(why).slice(0, 200) }, 502, cors);
    }

    if (env.MAILKV) {
      ctx.waitUntil(env.MAILKV.put(key, String(used + to.length), { expirationTtl: 172800 }));
    }

    return json({ ok: true, sent: to.length, failed: [], id: out.id || null }, 200, cors);
  }
};

/* ---------- helpers ---------- */

function corsHeaders(origin, env) {
  const allowed = (env.ALLOWED_ORIGINS || "https://weeksolved.com")
    .split(",").map(s => s.trim()).filter(Boolean);
  const ok = allowed.includes(origin) ? origin : allowed[0];
  return {
    "Access-Control-Allow-Origin": ok,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function json(obj, status, headers) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: Object.assign({ "Content-Type": "application/json" }, headers || {})
  });
}

/**
 * Check a Firebase ID token properly: real signature, right project, not expired.
 *
 * Google publishes the same signing keys in JWK form as well as X.509. The JWK
 * set imports straight into WebCrypto, so there is no certificate parsing here
 * to get subtly wrong. Keys are cached for an hour.
 */
let KEYCACHE = { at: 0, keys: null };

async function googleKeys() {
  if (KEYCACHE.keys && Date.now() - KEYCACHE.at < 3600000) return KEYCACHE.keys;
  const r = await fetch("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com");
  if (!r.ok) throw new Error("couldn't fetch signing keys");
  const set = await r.json();
  const byKid = {};
  (set.keys || []).forEach(k => { byKid[k.kid] = k; });
  KEYCACHE = { at: Date.now(), keys: byKid };
  return byKid;
}

function b64urlToBytes(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function verifyFirebaseToken(token, projectId) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new Error("malformed");

  let header, claims;
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
    claims = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1])));
  } catch (e) { throw new Error("malformed"); }

  if (header.alg !== "RS256") throw new Error("wrong algorithm");

  const now = Math.floor(Date.now() / 1000);
  if (claims.exp && claims.exp < now - 60) throw new Error("expired");
  if (claims.iat && claims.iat > now + 300) throw new Error("issued in the future");
  if (projectId) {
    if (claims.aud !== projectId) throw new Error("wrong project");
    if (claims.iss !== "https://securetoken.google.com/" + projectId) throw new Error("wrong issuer");
  }
  if (!claims.sub && !claims.user_id) throw new Error("no account in the token");

  const keys = await googleKeys();
  const jwk = keys[header.kid];
  if (!jwk) throw new Error("unknown signing key");

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlToBytes(parts[2]),
    new TextEncoder().encode(parts[0] + "." + parts[1])
  );
  if (!ok) throw new Error("bad signature");
  return claims;
}
