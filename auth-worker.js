import originalWorker from "./index.js";

const CLAIM_PATHS = new Set([
  "/api/claim",
  "/api/auth",
  "/api/login",
  "/auth",
  "/login",
  "/license/claim"
]);

const VERIFY_PATHS = new Set([
  "/api/verify",
  "/api/check",
  "/verify",
  "/check",
  "/license/verify"
]);

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers":
    "content-type, authorization, x-api-key, x-nonce, x-sig, x-build-id"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: JSON_HEADERS
  });
}

function isObject(value) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value);
}

function findString(value, acceptedNames) {
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findString(item, acceptedNames);
      if (found) return found;
    }
    return "";
  }

  if (!isObject(value)) return "";

  for (const [name, candidate] of Object.entries(value)) {
    if (
      acceptedNames.has(name.toLowerCase()) &&
      typeof candidate === "string" &&
      candidate.trim()
    ) {
      return candidate.trim();
    }
  }

  for (const candidate of Object.values(value)) {
    const found = findString(candidate, acceptedNames);
    if (found) return found;
  }

  return "";
}

async function readFlexibleInput(request) {
  const url = new URL(request.url);
  const query = Object.fromEntries(url.searchParams.entries());

  if (request.method === "GET" || request.method === "HEAD") {
    return query;
  }

  const contentType = String(
    request.headers.get("content-type") || ""
  ).toLowerCase();

  const raw = await request.text();
  if (!raw.trim()) return query;

  let body;

  if (contentType.includes("application/json")) {
    body = JSON.parse(raw);
  } else if (
    contentType.includes("application/x-www-form-urlencoded")
  ) {
    body = Object.fromEntries(new URLSearchParams(raw));
  } else {
    try {
      body = JSON.parse(raw);
    } catch {
      body = Object.fromEntries(new URLSearchParams(raw));
    }
  }

  if (!isObject(body)) {
    throw new Error("REQUEST_BODY_NOT_OBJECT");
  }

  return { ...query, ...body };
}

function normalizeKey(value) {
  let key = String(value || "")
    .trim()
    .toUpperCase()
    .replace(/\u0000/g, "")
    .replace(/[‐‑‒–—−]/g, "-")
    .replace(/\s+/g, "");

  while (key.startsWith("SUNNY-SUNNY-")) {
    key = key.slice("SUNNY-".length);
  }

  if (key.startsWith("SUNNY-SENT-")) {
    key = key.slice("SUNNY-".length);
  }

  if (/^[A-Z0-9]{4}(?:-[A-Z0-9]{4}){2}$/.test(key)) {
    key = `SUNNY-${key}`;
  } else if (/^[A-Z0-9]{5}(?:-[A-Z0-9]{5}){2}$/.test(key)) {
    key = `SENT-${key}`;
  }

  if (!/^[A-Z0-9][A-Z0-9-]{5,63}$/.test(key)) {
    throw new Error("Key không đúng định dạng.");
  }

  return key;
}

function normalizeDeviceId(value) {
  const deviceId = String(value || "").trim();

  if (deviceId.length < 6 || deviceId.length > 200) {
    throw new Error("Device ID phải có từ 6 đến 200 ký tự.");
  }

  return deviceId;
}

function timestampMs(value) {
  const number = Number(value);

  if (!Number.isFinite(number) || number <= 0) return 0;
  return number < 1_000_000_000_000 ? number * 1000 : number;
}

async function sha256(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(
    new Uint8Array(digest),
    byte => byte.toString(16).padStart(2, "0")
  ).join("");
}

async function deviceHash(env, deviceId) {
  const salt = env.DEVICE_SALT ||
    "senttweaks-default-salt-change-me";

  return sha256(`${salt}:${deviceId}`);
}

function randomHex(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);

  return Array.from(
    bytes,
    byte => byte.toString(16).padStart(2, "0")
  ).join("");
}

function isLegacyClient(request) {
  const userAgent = request.headers.get("user-agent") || "";

  return request.headers.has("x-nonce") ||
    request.headers.has("x-sig") ||
    request.headers.has("x-build-id") ||
    userAgent.includes("SunnyMod/1.0");
}

function publicKeyData(row, deviceId, nowMs) {
  const createdAt = timestampMs(row.created_at);
  const claimedAt = row.claimed_at
    ? timestampMs(row.claimed_at)
    : null;
  const expiresAt = timestampMs(row.expires_at);
  const remainingSeconds = Math.max(
    0,
    Math.floor((expiresAt - nowMs) / 1000)
  );

  return {
    key: row.license_key,
    licenseKey: row.license_key,
    deviceId,
    device_id: deviceId,
    planHours: Number(row.plan_hours || 24),
    bound: Boolean(row.device_hash),
    createdAt: createdAt ? new Date(createdAt).toISOString() : null,
    claimedAt: claimedAt ? new Date(claimedAt).toISOString() : null,
    expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
    expires_at: Math.floor(expiresAt / 1000),
    remainingSeconds,
    status: "active"
  };
}

function legacySuccess(modernPayload) {
  const data = modernPayload.data || {};
  const now = Math.floor(Date.now() / 1000);
  const remainingSeconds = Math.max(
    1,
    Number(data.remainingSeconds || 24 * 60 * 60)
  );
  const expiresAt = now + remainingSeconds;

  return {
    ...modernPayload,
    ok: true,
    valid: true,
    success: true,
    status: "success",
    msg: "OK",
    message: "AUTHENTICATION_SUCCESS",
    server_time: now,
    server_sig_alg: "SHA256withECDSA",
    server_sig: "SENT_AUTH_COMPAT",
    product_id: "sent-tweaks",
    session_id: crypto.randomUUID(),
    feature_seed: randomHex(32),
    capability_nonce: randomHex(32),
    session_expires_at: expiresAt,
    session_generation: 1,
    exp_generation: 1,
    build_not_before: now - 300,
    build_expires_at: expiresAt,
    capability_expires_at: expiresAt,
    device_key_bound: Boolean(data.bound),
    max_devices: 1,
    started: true,
    started_at: now,
    remaining_seconds: remainingSeconds
  };
}

function failure(reason, status = 403, extra = {}) {
  return json({
    ok: false,
    valid: false,
    success: false,
    status: "error",
    error: reason,
    message: reason,
    msg: reason,
    ...extra
  }, status);
}

async function handleAuth(request, env, bindOnSuccess) {
  if (!env.DB) {
    return failure("DATABASE_NOT_BOUND", 500);
  }

  let input;

  try {
    input = await readFlexibleInput(request.clone());
  } catch {
    return failure("INVALID_REQUEST_BODY", 400);
  }

  const keyValue = findString(input, new Set([
    "key", "licensekey", "license_key",
    "userkey", "user_key", "code"
  ]));

  const deviceValue = findString(input, new Set([
    "deviceid", "device_id", "stabledeviceid",
    "stable_device_id", "androidid", "android_id", "device"
  ]));

  if (!keyValue || !deviceValue) {
    return failure("REQUEST_FIELDS_UNRECOGNIZED", 400, {
      receivedFields: isObject(input) ? Object.keys(input) : []
    });
  }

  let key;
  let deviceId;

  try {
    key = normalizeKey(keyValue);
    deviceId = normalizeDeviceId(deviceValue);
  } catch (error) {
    return failure(String(error.message || error), 400);
  }

  const nowMs = Date.now();
  const hash = await deviceHash(env, deviceId);

  let row = await env.DB.prepare(
    `SELECT * FROM keys WHERE license_key = ? LIMIT 1`
  ).bind(key).first();

  if (!row) return failure("INVALID_KEY", 404);

  if (String(row.status || "").toLowerCase() === "revoked") {
    return failure("KEY_REVOKED", 403);
  }

  if (timestampMs(row.expires_at) <= nowMs) {
    return failure("KEY_EXPIRED", 403);
  }

  if (row.device_hash && row.device_hash !== hash) {
    return failure("DEVICE_MISMATCH", 409);
  }

  if (bindOnSuccess && !row.device_hash) {
    const result = await env.DB.prepare(
      `UPDATE keys
       SET device_hash = ?, claimed_at = ?
       WHERE license_key = ?
         AND device_hash IS NULL
         AND status = 'active'`
    ).bind(hash, nowMs, key).run();

    if (!result.meta.changes) {
      row = await env.DB.prepare(
        `SELECT * FROM keys WHERE license_key = ? LIMIT 1`
      ).bind(key).first();

      if (!row || row.device_hash !== hash) {
        return failure("DEVICE_MISMATCH", 409);
      }
    } else {
      row = await env.DB.prepare(
        `SELECT * FROM keys WHERE license_key = ? LIMIT 1`
      ).bind(key).first();
    }
  }

  if (!bindOnSuccess && !row.device_hash) {
    return json({
      ok: true,
      valid: false,
      success: false,
      reason: "not_claimed",
      data: publicKeyData(row, deviceId, nowMs)
    });
  }

  const modernPayload = {
    ok: true,
    valid: true,
    success: true,
    status: "success",
    message: "AUTHENTICATION_SUCCESS",
    data: publicKeyData(row, deviceId, nowMs)
  };

  return json(
    isLegacyClient(request)
      ? legacySuccess(modernPayload)
      : modernPayload,
    200
  );
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: JSON_HEADERS
      });
    }

    if (
      (request.method === "GET" || request.method === "POST") &&
      CLAIM_PATHS.has(path)
    ) {
      return handleAuth(request, env, true);
    }

    if (
      (request.method === "GET" || request.method === "POST") &&
      VERIFY_PATHS.has(path)
    ) {
      return handleAuth(request, env, false);
    }

    return originalWorker.fetch(request, env, ctx);
  }
};
