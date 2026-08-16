// Sent Tweaks gateway.
// FREE: Link4m keys use the existing /api/claim + /api/verify flow.
// VIP : admin-only keys are tagged in D1 table vip_keys.
// Existing index.js remains responsible for expiry, device binding,
// Auth V4 signatures and legacy-client compatibility.
import signedWorker from "./index.js";

const AUTH_PROTOCOL_VERSION = 4;
const DEFAULT_BUILD_ID = "sent-menu-2026.08.07-r1";
const DEFAULT_CLIENT_VERSION = "5.2.1";

const VN_OFFSET_MS = 7 * 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const MULTI_DEVICE_PREFIX = "SENTMULTI:v1:";
const VIP_PRODUCT_HEADER = "x-sent-product";
const VIP_PRODUCT_VALUE = "vip";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: JSON_HEADERS
  });
}

function firstString(source, names) {
  for (const name of names) {
    const value = source?.[name];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return "";
}

function randomNonceHex(byteLength = 24) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(
    bytes,
    byte => byte.toString(16).padStart(2, "0")
  ).join("");
}

function randomPart(length = 5) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(
    bytes,
    byte => alphabet[byte % alphabet.length]
  ).join("");
}

function createVipKey() {
  // Still matches SENT-XXXXX-XXXXX-XXXXX used by index.js.
  // The vip_keys table is the real authorization flag.
  return `SENT-VIP${randomPart(2)}-${randomPart(5)}-${randomPart(5)}`;
}

function createAdminFreeKey() {
  // Visual prefix only. Absence from vip_keys is the real FREE authorization.
  // It still matches the existing SENT-XXXXX-XXXXX-XXXXX parser in index.js.
  return `SENT-FREE${randomPart(1)}-${randomPart(5)}-${randomPart(5)}`;
}

function normalizeDatabaseKey(value) {
  let key = String(value ?? "")
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

  if (/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key)) {
    key = `SUNNY-${key}`;
  } else if (/^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(key)) {
    key = `SENT-${key}`;
  }

  return key;
}

function looksLikeModernV4(body) {
  return (
    typeof body === "object" &&
    body !== null &&
    typeof body.nonce === "string" &&
    /^[a-fA-F0-9]{48}$/.test(body.nonce.trim()) &&
    Number.isSafeInteger(Number(body.clientTimeMs ?? body.client_time_ms)) &&
    Number(body.clientTimeMs ?? body.client_time_ms) > 0 &&
    Number(body.protocolVersion ?? body.protocol_version) === AUTH_PROTOCOL_VERSION &&
    Boolean(firstString(body, ["buildId", "build_id"])) &&
    Boolean(firstString(body, ["clientVersion", "client_version", "version"]))
  );
}

async function upgradeLegacyJsonRequest(request, env) {
  const contentType = String(
    request.headers.get("content-type") || ""
  ).toLowerCase();

  if (!contentType.includes("application/json")) {
    return request;
  }

  let body;
  try {
    body = await request.clone().json();
  } catch {
    return request;
  }

  if (looksLikeModernV4(body)) {
    return request;
  }

  const key = firstString(body, [
    "key", "licenseKey", "license_key", "userKey", "user_key", "code"
  ]);

  const deviceId = firstString(body, [
    "deviceId", "device_id", "stableDeviceId", "stable_device_id",
    "androidId", "android_id", "device"
  ]);

  if (!key || !deviceId) {
    return request;
  }

  const upgraded = {
    ...body,
    key,
    deviceId,
    nonce: randomNonceHex(),
    clientTimeMs: Date.now(),
    protocolVersion: AUTH_PROTOCOL_VERSION,
    buildId: String(env.AUTH_ACTIVE_BUILD_ID || DEFAULT_BUILD_ID),
    clientVersion: String(env.AUTH_CLIENT_VERSION || DEFAULT_CLIENT_VERSION)
  };

  const headers = new Headers(request.headers);
  headers.set("content-type", "application/json");
  headers.delete("content-length");

  return new Request(request.url, {
    method: request.method,
    headers,
    body: JSON.stringify(upgraded)
  });
}

function isAdmin(request, env) {
  const expected = String(env.ADMIN_TOKEN || "");
  return Boolean(expected) &&
    request.headers.get("authorization") === `Bearer ${expected}`;
}

function vietnamDayBounds(now = Date.now()) {
  const todayStart =
    Math.floor((now + VN_OFFSET_MS) / DAY_MS) * DAY_MS - VN_OFFSET_MS;

  return {
    yesterdayStart: todayStart - DAY_MS,
    todayStart,
    tomorrowStart: todayStart + DAY_MS
  };
}

function normalizeMaxDevices(value) {
  const maxDevices = Number(value ?? 1);

  if (!Number.isInteger(maxDevices) || maxDevices < 0 || maxDevices > 100) {
    throw new Error(
      "Giới hạn thiết bị phải từ 0 đến 100. Dùng 0 để không giới hạn."
    );
  }

  return maxDevices;
}

function normalizeFreePlanHours(value) {
  const planHours = Number(value);
  const allowed = new Set([12, 24, 72, 168, 720]);

  if (!Number.isInteger(planHours) || !allowed.has(planHours)) {
    throw new Error(
      "Gói Free không hợp lệ. Hỗ trợ 12h, 24h, 3 ngày, 7 ngày hoặc 30 ngày."
    );
  }

  return planHours;
}

function normalizeVipPlanHours(value) {
  const planHours = Number(value);
  const allowed = new Set([12, 24, 72, 168, 720, 2160]);

  if (!Number.isInteger(planHours) || !allowed.has(planHours)) {
    throw new Error(
      "Gói VIP không hợp lệ. Hỗ trợ 12h, 24h, 3 ngày, 7 ngày, 30 ngày hoặc 90 ngày."
    );
  }

  return planHours;
}

function normalizeNote(value) {
  return String(value || "").trim().slice(0, 160);
}

function serializeDeviceBinding(limit, hashes = []) {
  return `${MULTI_DEVICE_PREFIX}${limit}:${[...new Set(hashes)].join(",")}`;
}

function deviceBindingInfo(value) {
  const raw = String(value || "").trim();

  if (!raw) {
    return { maxDevices: 1, devicesUsed: 0, bound: false };
  }

  if (!raw.startsWith(MULTI_DEVICE_PREFIX)) {
    return { maxDevices: 1, devicesUsed: 1, bound: true };
  }

  const payload = raw.slice(MULTI_DEVICE_PREFIX.length);
  const separator = payload.indexOf(":");

  if (separator < 0) {
    return { maxDevices: 1, devicesUsed: 1, bound: true };
  }

  const limit = Number(payload.slice(0, separator));
  const hashes = payload
    .slice(separator + 1)
    .split(",")
    .map(item => item.trim())
    .filter(Boolean);

  return {
    maxDevices: Number.isInteger(limit) ? limit : 1,
    devicesUsed: new Set(hashes).size,
    bound: hashes.length > 0
  };
}

function mapKeyRow(row, now = Date.now()) {
  const expiresAt = Number(row.expires_at);
  const createdAt = Number(row.created_at);
  const binding = deviceBindingInfo(row.device_hash);

  let status = "active";

  if (row.status === "revoked") {
    status = "revoked";
  } else if (!Number.isFinite(expiresAt) || now >= expiresAt) {
    status = "expired";
  }

  return {
    key: row.license_key,
    planHours: Number(row.plan_hours || 0),
    bound: binding.bound,
    maxDevices: binding.maxDevices,
    devicesUsed: binding.devicesUsed,
    createdAt: new Date(
      Number.isFinite(createdAt) ? createdAt : now
    ).toISOString(),
    claimedAt: row.claimed_at
      ? new Date(Number(row.claimed_at)).toISOString()
      : null,
    expiresAt: Number.isFinite(expiresAt)
      ? new Date(expiresAt).toISOString()
      : null,
    expiresAtMs: Number.isFinite(expiresAt) ? expiresAt : null,
    remainingSeconds: Number.isFinite(expiresAt)
      ? Math.max(0, Math.floor((expiresAt - now) / 1000))
      : 0,
    status,
    note: String(row.vip_note || row.note || "")
  };
}

/* VIP schema */

let vipSchemaReadyPromise = null;

function ensureVipSchema(env) {
  if (!vipSchemaReadyPromise) {
    vipSchemaReadyPromise = (async () => {
      if (!env.DB) {
        throw new Error("D1 database chưa được liên kết với Worker.");
      }

      await env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS vip_keys (
           license_key TEXT PRIMARY KEY,
           created_at INTEGER NOT NULL,
           note TEXT
         )`
      ).run();

      await env.DB.prepare(
        `CREATE INDEX IF NOT EXISTS idx_vip_keys_created_at
         ON vip_keys(created_at)`
      ).run();

      return true;
    })().catch(error => {
      vipSchemaReadyPromise = null;
      throw error;
    });
  }

  return vipSchemaReadyPromise;
}

async function isVipKey(env, key) {
  await ensureVipSchema(env);

  const normalized = normalizeDatabaseKey(key);

  if (!normalized) {
    return false;
  }

  const row = await env.DB.prepare(
    `SELECT license_key
     FROM vip_keys
     WHERE license_key = ?
     LIMIT 1`
  )
    .bind(normalized)
    .first();

  return Boolean(row);
}

async function extractSubmittedKey(request) {
  const contentType = String(
    request.headers.get("content-type") || ""
  ).toLowerCase();

  if (contentType.includes("application/json")) {
    try {
      const body = await request.clone().json();

      return {
        key: normalizeDatabaseKey(firstString(body, [
          "key", "licenseKey", "license_key", "userKey", "user_key", "code"
        ])),
        kind: "json"
      };
    } catch {
      return { key: "", kind: "json" };
    }
  }

  try {
    const raw = await request.clone().text();
    const form = new URLSearchParams(raw);

    const isLibloader =
      form.has("user_key") ||
      form.has("serial") ||
      form.has("package");

    return {
      key: normalizeDatabaseKey(
        form.get("user_key") ||
        form.get("key") ||
        form.get("license_key") ||
        form.get("code") ||
        ""
      ),
      kind: isLibloader ? "libloader" : "legacy"
    };
  } catch {
    return { key: "", kind: "legacy" };
  }
}

function accessDeniedResponse(info, code, message, status = 403) {
  if (info?.kind === "libloader") {
    return json({
      status: false,
      reason: message,
      code
    }, status);
  }

  return json({
    ok: false,
    valid: false,
    error: code,
    reason: message
  }, status);
}

async function rewriteRequestPath(request, newPath) {
  const url = new URL(request.url);
  url.pathname = newPath;

  const headers = new Headers(request.headers);
  headers.delete("content-length");

  const init = {
    method: request.method,
    headers,
    redirect: request.redirect
  };

  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body = await request.clone().arrayBuffer();
  }

  return new Request(url.toString(), init);
}


/* =========================================================
 * LINK4M HISTORY V3 — immutable analytics
 *
 * Completed Link4m sessions are copied to link4m_history and never
 * deleted by session cleanup. This prevents "yesterday" from shrinking
 * during the day.
 * ========================================================= */

let link4mHistoryReadyPromise = null;

function randomToken(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);

  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(String(text));
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(
    new Uint8Array(digest),
    byte => byte.toString(16).padStart(2, "0")
  ).join("");
}

function ensureLink4mHistory(env) {
  if (!link4mHistoryReadyPromise) {
    link4mHistoryReadyPromise = (async () => {
      if (!env.DB) {
        throw new Error("D1 database chưa được liên kết với Worker.");
      }

      await env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS link4m_history (
           license_key TEXT PRIMARY KEY,
           completed_at INTEGER NOT NULL
         )`
      ).run();

      await env.DB.prepare(
        `CREATE INDEX IF NOT EXISTS idx_link4m_history_completed_at
         ON link4m_history(completed_at)`
      ).run();

      // One-time/continuous backfill from all completed sessions that
      // still exist. INSERT OR IGNORE makes this safe on every cold start.
      await env.DB.prepare(
        `INSERT OR IGNORE INTO link4m_history (
           license_key,
           completed_at
         )
         SELECT
           license_key,
           completed_at
         FROM link_sessions
         WHERE completed_at IS NOT NULL
           AND license_key IS NOT NULL`
      ).run();

      return true;
    })().catch(error => {
      link4mHistoryReadyPromise = null;
      throw error;
    });
  }

  return link4mHistoryReadyPromise;
}

async function recordCompletedLink4mSession(env, sessionHash) {
  await ensureLink4mHistory(env);

  const row = await env.DB.prepare(
    `SELECT
       license_key,
       completed_at
     FROM link_sessions
     WHERE session_hash = ?
       AND completed_at IS NOT NULL
       AND license_key IS NOT NULL
     LIMIT 1`
  )
    .bind(sessionHash)
    .first();

  if (!row) {
    return false;
  }

  await env.DB.prepare(
    `INSERT OR IGNORE INTO link4m_history (
       license_key,
       completed_at
     )
     VALUES (?, ?)`
  )
    .bind(
      row.license_key,
      Number(row.completed_at)
    )
    .run();

  return true;
}

async function handleSafeLink4mStart(request, env) {
  const apiToken = String(
    env.LINK4M_API_TOKEN || ""
  ).trim();

  if (!apiToken) {
    return json({
      ok: false,
      error: "Máy chủ chưa cấu hình LINK4M_API_TOKEN."
    }, 503);
  }

  await ensureLink4mHistory(env);

  const now = Date.now();
  const expiresAt =
    now + 20 * 60 * 1000;

  const sessionToken =
    randomToken(32);

  const sessionHash =
    await sha256Hex(sessionToken);

  // IMPORTANT:
  // Only abandoned/incomplete sessions may be removed.
  // Never remove completed sessions because they are historical analytics.
  await env.DB.prepare(
    `DELETE FROM link_sessions
     WHERE completed_at IS NULL
       AND expires_at < ?`
  )
    .bind(
      now - 24 * 60 * 60 * 1000
    )
    .run();

  await env.DB.prepare(
    `INSERT INTO link_sessions (
       session_hash,
       created_at,
       expires_at
     )
     VALUES (?, ?, ?)`
  )
    .bind(
      sessionHash,
      now,
      expiresAt
    )
    .run();

  const callbackUrl =
    new URL(
      "/senttwgetkey",
      request.url
    );

  callbackUrl.searchParams.set(
    "session",
    sessionToken
  );

  const link4mApi =
    new URL(
      "https://link4m.co/api-shorten/v2"
    );

  link4mApi.searchParams.set(
    "api",
    apiToken
  );

  link4mApi.searchParams.set(
    "url",
    callbackUrl.toString()
  );

  try {
    const response =
      await fetch(
        link4mApi.toString(),
        {
          method: "GET",
          headers: {
            accept: "application/json"
          }
        }
      );

    const raw =
      await response.text();

    let result;

    try {
      result =
        JSON.parse(raw);
    } catch {
      throw new Error(
        "Link4m trả về dữ liệu không hợp lệ."
      );
    }

    if (
      !response.ok ||
      String(result.status || "")
        .toLowerCase() !== "success"
    ) {
      throw new Error(
        result.message ||
        "Link4m không thể tạo liên kết."
      );
    }

    const shortUrl =
      result.shortenedUrl ||
      result.shortened_url ||
      result.shortUrl;

    if (
      !shortUrl ||
      !/^https?:\/\//i.test(shortUrl)
    ) {
      throw new Error(
        "Link4m không trả về đường dẫn rút gọn."
      );
    }

    return json({
      ok: true,
      shortUrl
    });
  } catch (error) {
    await env.DB.prepare(
      `DELETE FROM link_sessions
       WHERE session_hash = ?
         AND completed_at IS NULL`
    )
      .bind(sessionHash)
      .run();

    throw error;
  }
}

async function forwardAndRecordLink4mComplete(
  request,
  env,
  ctx
) {
  let sessionHash = "";

  try {
    const body =
      await request.clone().json();

    const token =
      String(
        body?.sessionToken || ""
      ).trim();

    if (token) {
      sessionHash =
        await sha256Hex(token);
    }
  } catch {
    // index.js will return its existing validation error.
  }

  const response =
    await signedWorker.fetch(
      request,
      env,
      ctx
    );

  if (
    sessionHash &&
    response.ok
  ) {
    try {
      const payload =
        await response.clone().json();

      if (
        payload?.ok === true &&
        payload?.data?.key
      ) {
        await recordCompletedLink4mSession(
          env,
          sessionHash
        );
      }
    } catch {
      // Never break a successful Get Key response because analytics failed.
    }
  }

  return response;
}


/* FREE / Link4m analytics V2 */

function mapRecentLink4mRow(row, now) {
  const mapped = mapKeyRow(row, now);

  return {
    ...mapped,
    createdAt: new Date(
      Number(row.completed_at || row.created_at || now)
    ).toISOString()
  };
}

async function handleAccurateLink4mStats(request, env) {
  if (!isAdmin(request, env)) {
    return json({
      ok: false,
      error: "Không có quyền xem thống kê."
    }, 401);
  }

  if (!env.DB) {
    return json({
      ok: false,
      error: "D1 database chưa được liên kết với Worker."
    }, 503);
  }

  await ensureLink4mHistory(env);

  const now = Date.now();
  const {
    yesterdayStart,
    todayStart,
    tomorrowStart
  } = vietnamDayBounds(now);

  const summary = await env.DB.prepare(
    `SELECT
       COUNT(*) AS completed_sessions,
       COUNT(DISTINCT h.license_key) AS total,
       COUNT(DISTINCT CASE
         WHEN h.completed_at >= ?
          AND h.completed_at < ?
         THEN h.license_key
       END) AS today,
       COUNT(DISTINCT CASE
         WHEN h.completed_at >= ?
          AND h.completed_at < ?
         THEN h.license_key
       END) AS yesterday,
       COUNT(DISTINCT CASE
         WHEN k.status = 'active'
          AND k.expires_at > ?
         THEN h.license_key
       END) AS active,
       COUNT(DISTINCT CASE
         WHEN k.status != 'revoked'
          AND k.expires_at <= ?
         THEN h.license_key
       END) AS expired,
       COUNT(DISTINCT CASE
         WHEN k.status = 'revoked'
         THEN h.license_key
       END) AS revoked
     FROM link4m_history AS h
     LEFT JOIN keys AS k
       ON k.license_key = h.license_key`
  )
    .bind(
      todayStart,
      tomorrowStart,
      yesterdayStart,
      todayStart,
      now,
      now
    )
    .first();

  const recentResult = await env.DB.prepare(
    `SELECT
       h.license_key,
       h.completed_at,
       k.plan_hours,
       k.device_hash,
       k.claimed_at,
       k.created_at,
       k.expires_at,
       k.status
     FROM link4m_history AS h
     INNER JOIN keys AS k
       ON k.license_key = h.license_key
     ORDER BY h.completed_at DESC
     LIMIT 20`
  ).all();

  const recent =
    (recentResult.results || [])
      .map(
        row =>
          mapRecentLink4mRow(
            row,
            now
          )
      );

  const today =
    Number(
      summary?.today || 0
    );

  const yesterday =
    Number(
      summary?.yesterday || 0
    );

  const difference =
    today - yesterday;

  let percentChange = 0;

  if (yesterday > 0) {
    percentChange =
      Math.round(
        (difference / yesterday) *
        10000
      ) / 100;
  } else if (today > 0) {
    percentChange = 100;
  }

  return json({
    ok: true,
    generatedAt:
      new Date(now).toISOString(),
    serverTimeMs: now,
    timeZone:
      "Asia/Ho_Chi_Minh",
    integrity: {
      source:
        "link4m_history",
      immutableCompletedHistory:
        true,
      completedSessionCleanup:
        "incomplete_only",
      note:
        "Completed Link4m records are retained and daily windows are fixed to UTC+7."
    },
    dayBounds: {
      yesterdayStartMs:
        yesterdayStart,
      todayStartMs:
        todayStart,
      tomorrowStartMs:
        tomorrowStart,
      yesterdayStart:
        new Date(
          yesterdayStart
        ).toISOString(),
      todayStart:
        new Date(
          todayStart
        ).toISOString(),
      tomorrowStart:
        new Date(
          tomorrowStart
        ).toISOString()
    },
    stats: {
      completedSessions:
        Number(
          summary?.completed_sessions ||
          0
        ),
      total:
        Number(
          summary?.total || 0
        ),
      today,
      yesterday,
      active:
        Number(
          summary?.active || 0
        ),
      expired:
        Number(
          summary?.expired || 0
        ),
      revoked:
        Number(
          summary?.revoked || 0
        ),
      todayVsYesterday: {
        difference,
        percentChange
      }
    },
    recent
  });
}

/* FREE admin APIs
 *
 * These keys are created only from the secret Admin page.
 * They are deliberately NOT inserted into link4m_history, so Link4m
 * analytics remain an exact count of users who actually completed Link4m.
 * They are also NOT inserted into vip_keys, therefore the FREE product gate
 * accepts them and the VIP product gate rejects them.
 */

async function insertUniqueAdminFreeKey(env, planHours, maxDevices) {
  if (!env.DB) {
    throw new Error("D1 database chưa được liên kết với Worker.");
  }

  const now = Date.now();
  const expiresAt = now + planHours * 60 * 60 * 1000;

  const initialBinding =
    maxDevices === 1
      ? null
      : serializeDeviceBinding(maxDevices, []);

  for (let attempt = 0; attempt < 8; attempt += 1) {
    const licenseKey = createAdminFreeKey();

    try {
      await env.DB.prepare(
        `INSERT INTO keys (
           license_key,
           plan_hours,
           device_hash,
           created_at,
           expires_at,
           status
         )
         VALUES (?, ?, ?, ?, ?, 'active')`
      )
        .bind(
          licenseKey,
          planHours,
          initialBinding,
          now,
          expiresAt
        )
        .run();

      return {
        license_key: licenseKey,
        plan_hours: planHours,
        device_hash: initialBinding,
        created_at: now,
        claimed_at: null,
        expires_at: expiresAt,
        status: "active"
      };
    } catch (error) {
      const message = String(error).toLowerCase();

      if (
        message.includes("unique") ||
        message.includes("constraint")
      ) {
        continue;
      }

      throw error;
    }
  }

  throw new Error(
    "Không thể tạo key Free mới. Hãy thử lại."
  );
}

async function handleAdminFreeCreate(request, env) {
  if (!isAdmin(request, env)) {
    return json({
      ok: false,
      error: "Không có quyền tạo key Free."
    }, 401);
  }

  const body = await request.json().catch(() => ({}));
  const planHours = normalizeFreePlanHours(body.planHours);
  const maxDevices = normalizeMaxDevices(body.maxDevices);

  const row = await insertUniqueAdminFreeKey(
    env,
    planHours,
    maxDevices
  );

  return json({
    ok: true,
    vip: false,
    source: "admin_free",
    data: mapKeyRow(row, Date.now())
  }, 201);
}

/* VIP admin APIs */

async function insertUniqueVipKey(env, planHours, maxDevices, note) {
  await ensureVipSchema(env);

  const now = Date.now();
  const expiresAt =
    now + planHours * 60 * 60 * 1000;

  const initialBinding =
    maxDevices === 1
      ? null
      : serializeDeviceBinding(maxDevices, []);

  for (let attempt = 0; attempt < 8; attempt += 1) {
    const licenseKey = createVipKey();

    try {
      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO keys (
             license_key,
             plan_hours,
             device_hash,
             created_at,
             expires_at,
             status
           )
           VALUES (?, ?, ?, ?, ?, 'active')`
        ).bind(
          licenseKey,
          planHours,
          initialBinding,
          now,
          expiresAt
        ),

        env.DB.prepare(
          `INSERT INTO vip_keys (
             license_key,
             created_at,
             note
           )
           VALUES (?, ?, ?)`
        ).bind(
          licenseKey,
          now,
          note
        )
      ]);

      return {
        license_key: licenseKey,
        plan_hours: planHours,
        device_hash: initialBinding,
        created_at: now,
        claimed_at: null,
        expires_at: expiresAt,
        status: "active",
        vip_note: note
      };
    } catch (error) {
      const message = String(error).toLowerCase();

      if (
        message.includes("unique") ||
        message.includes("constraint")
      ) {
        continue;
      }

      throw error;
    }
  }

  throw new Error(
    "Không thể tạo key VIP mới. Hãy thử lại."
  );
}

async function handleAdminVipCreate(request, env) {
  if (!isAdmin(request, env)) {
    return json({
      ok: false,
      error: "Không có quyền tạo key VIP."
    }, 401);
  }

  const body = await request.json().catch(() => ({}));

  const planHours = normalizeVipPlanHours(body.planHours);
  const maxDevices = normalizeMaxDevices(body.maxDevices);
  const note = normalizeNote(body.note);

  const row = await insertUniqueVipKey(
    env,
    planHours,
    maxDevices,
    note
  );

  return json({
    ok: true,
    vip: true,
    data: mapKeyRow(row, Date.now())
  }, 201);
}

async function handleAdminVipStats(request, env) {
  if (!isAdmin(request, env)) {
    return json({
      ok: false,
      error: "Không có quyền xem key VIP."
    }, 401);
  }

  await ensureVipSchema(env);

  const now = Date.now();

  const summary = await env.DB.prepare(
    `SELECT
       COUNT(*) AS total,
       COUNT(CASE
         WHEN k.status = 'active'
          AND k.expires_at > ?
         THEN 1
       END) AS active,
       COUNT(CASE
         WHEN k.status != 'revoked'
          AND k.expires_at <= ?
         THEN 1
       END) AS expired,
       COUNT(CASE
         WHEN k.status = 'revoked'
         THEN 1
       END) AS revoked
     FROM vip_keys AS v
     INNER JOIN keys AS k
       ON k.license_key = v.license_key`
  )
    .bind(now, now)
    .first();

  const recentResult = await env.DB.prepare(
    `SELECT
       k.license_key,
       k.plan_hours,
       k.device_hash,
       k.claimed_at,
       k.created_at,
       k.expires_at,
       k.status,
       v.note AS vip_note
     FROM vip_keys AS v
     INNER JOIN keys AS k
       ON k.license_key = v.license_key
     ORDER BY v.created_at DESC
     LIMIT 50`
  ).all();

  return json({
    ok: true,
    generatedAt: new Date(now).toISOString(),
    stats: {
      total: Number(summary?.total || 0),
      active: Number(summary?.active || 0),
      expired: Number(summary?.expired || 0),
      revoked: Number(summary?.revoked || 0)
    },
    recent: (recentResult.results || [])
      .map(row => mapKeyRow(row, now))
  });
}

async function handleAdminMarkVip(request, env) {
  if (!isAdmin(request, env)) {
    return json({
      ok: false,
      error: "Không có quyền."
    }, 401);
  }

  await ensureVipSchema(env);

  const body = await request.json().catch(() => ({}));
  const key = normalizeDatabaseKey(body.key);

  const existing = await env.DB.prepare(
    `SELECT license_key
     FROM keys
     WHERE license_key = ?
     LIMIT 1`
  )
    .bind(key)
    .first();

  if (!existing) {
    return json({
      ok: false,
      error: "Không tìm thấy key."
    }, 404);
  }

  await env.DB.prepare(
    `INSERT OR IGNORE INTO vip_keys (
       license_key,
       created_at,
       note
     )
     VALUES (?, ?, ?)`
  )
    .bind(
      key,
      Date.now(),
      normalizeNote(body.note)
    )
    .run();

  return json({
    ok: true,
    key,
    vip: true
  });
}

/* FREE/VIP product gate */

function requestWantsVip(request) {
  return String(
    request.headers.get(VIP_PRODUCT_HEADER) || ""
  )
    .trim()
    .toLowerCase() === VIP_PRODUCT_VALUE;
}

async function enforceProductGate(request, env, requireVip) {
  const info = await extractSubmittedKey(request);

  if (!info.key) {
    return {
      allowed: true,
      info,
      isVip: false
    };
  }

  const vip = await isVipKey(env, info.key);

  if (requireVip && !vip) {
    return {
      allowed: false,
      info,
      isVip: false,
      response: accessDeniedResponse(
        info,
        "FREE_KEY_NOT_ALLOWED_IN_VIP_APP",
        "Key Free/Link4m không được phép đăng nhập app VIP.",
        403
      )
    };
  }

  if (!requireVip && vip) {
    return {
      allowed: false,
      info,
      isVip: true,
      response: accessDeniedResponse(
        info,
        "VIP_KEY_REQUIRES_VIP_APP",
        "Đây là key VIP. Key này chỉ được phép đăng nhập app VIP.",
        403
      )
    };
  }

  return {
    allowed: true,
    info,
    isVip: vip
  };
}

async function forwardVipAlias(request, env, ctx, targetPath) {
  const gate = await enforceProductGate(
    request,
    env,
    true
  );

  if (!gate.allowed) {
    return gate.response;
  }

  let forwarded = await rewriteRequestPath(
    request,
    targetPath
  );

  if (
    targetPath === "/api/claim" ||
    targetPath === "/api/verify"
  ) {
    forwarded = await upgradeLegacyJsonRequest(
      forwarded,
      env
    );
  }

  return signedWorker.fetch(
    forwarded,
    env,
    ctx
  );
}


/* =========================================================
 * GET MOD — VIP-authenticated feature asset delivery
 * Only this endpoint is added. Existing routes remain unchanged.
 * ========================================================= */

function getModSafeSegment(value, fallback = "default") {
  const text = String(value ?? "").trim().slice(0, 80) || fallback;
  return text.replace(/[^A-Za-z0-9_.:+*\-]/g, "_");
}

function getModJson(data, status = 200) {
  return json(data, status);
}

async function handleGetMod(request, env, ctx) {
  if (request.method === "GET") {
    return getModJson({
      ok: true,
      service: "get_mod.php",
      method: "POST",
      vipOnly: true,
      storage: "workers-kv",
      kvBound: Boolean(env.FEATURES_KV)
    });
  }

  if (request.method !== "POST") {
    return getModJson({
      status: false,
      error: "METHOD_NOT_ALLOWED"
    }, 405);
  }

  const contentType = String(
    request.headers.get("content-type") || ""
  ).toLowerCase();

  let key = "";
  let deviceId = "";
  let feature = "";
  let mode = "default";
  let game = "default";
  let appVersion = "default";

  if (contentType.includes("application/json")) {
    const body = await request.json().catch(() => ({}));

    key = firstString(body, [
      "key_code",
      "key",
      "licenseKey",
      "license_key",
      "code"
    ]);

    deviceId = firstString(body, [
      "udid",
      "deviceId",
      "device_id",
      "device"
    ]);

    feature = firstString(body, [
      "feature",
      "mod",
      "name"
    ]);

    mode = firstString(body, ["mode"]) || "default";
    game = firstString(body, ["game"]) || "default";
    appVersion =
      firstString(body, ["app_ver", "appVersion", "version"]) ||
      "default";
  } else {
    const form = new URLSearchParams(
      await request.text()
    );

    key =
      form.get("key_code") ||
      form.get("key") ||
      form.get("license_key") ||
      form.get("code") ||
      "";

    deviceId =
      form.get("udid") ||
      form.get("deviceId") ||
      form.get("device_id") ||
      form.get("device") ||
      "";

    feature =
      form.get("feature") ||
      form.get("mod") ||
      form.get("name") ||
      "";

    mode = form.get("mode") || "default";
    game = form.get("game") || "default";
    appVersion =
      form.get("app_ver") ||
      form.get("appVersion") ||
      form.get("version") ||
      "default";
  }

  key = normalizeDatabaseKey(key);
  deviceId = String(deviceId || "").trim();
  feature = getModSafeSegment(feature, "");
  mode = getModSafeSegment(mode);
  game = getModSafeSegment(game);
  appVersion = getModSafeSegment(appVersion);

  if (!key || !deviceId || !feature) {
    return getModJson({
      status: false,
      error: "MISSING_FIELDS",
      message: "Thiếu key_code, udid hoặc feature."
    }, 400);
  }

  /*
   * Reuse the existing VIP claim path instead of duplicating license,
   * expiry and device-binding logic.
   */
  const authUrl = new URL(request.url);
  authUrl.pathname = "/api/vip/claim";
  authUrl.search = "";

  const authRequest = new Request(
    authUrl.toString(),
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "accept": "application/json"
      },
      body: JSON.stringify({
        key,
        deviceId
      })
    }
  );

  const authResponse =
    await forwardVipAlias(
      authRequest,
      env,
      ctx,
      "/api/claim"
    );

  if (!authResponse.ok) {
    const raw = await authResponse.text();

    try {
      const payload = JSON.parse(raw);
      return getModJson({
        status: false,
        error:
          payload.error ||
          payload.reason ||
          "VIP_AUTH_FAILED",
        message:
          payload.reason ||
          payload.message ||
          payload.error ||
          "Key VIP không hợp lệ."
      }, authResponse.status || 403);
    } catch {
      return getModJson({
        status: false,
        error: "VIP_AUTH_FAILED",
        message: raw || "Key VIP không hợp lệ."
      }, authResponse.status || 403);
    }
  }

  let authPayload = null;

  try {
    authPayload =
      await authResponse.clone().json();
  } catch {}

  if (
    authPayload?.valid !== true ||
    String(
      authPayload?.data?.status || ""
    ).toLowerCase() !== "active"
  ) {
    return getModJson({
      status: false,
      error: "VIP_AUTH_FAILED",
      message: "Key VIP không còn hiệu lực."
    }, 403);
  }

  if (!env.FEATURES_KV || typeof env.FEATURES_KV.get !== "function") {
    return getModJson({
      status: false,
      error: "FEATURES_KV_NOT_BOUND",
      message: "Kho KV sent-features chưa được liên kết."
    }, 503);
  }

  const candidates = [
    `features/${game}/${feature}/${mode}/${appVersion}.bin`,
    `features/${game}/${feature}/${mode}/default.bin`,
    `features/${game}/${feature}/default.bin`,
    `features/${feature}.bin`
  ];

  for (const storageKey of candidates) {
    const value = await env.FEATURES_KV.get(
      storageKey,
      { type: "arrayBuffer" }
    );

    if (value === null) {
      continue;
    }

    const headers = new Headers({
      "content-type": "application/octet-stream",
      "cache-control": "no-store",
      "x-sent-feature": feature,
      "x-sent-storage": "kv",
      "x-sent-storage-key": storageKey
    });

    return new Response(
      value,
      {
        status: 200,
        headers
      }
    );
  }

  return getModJson({
    status: false,
    error: "FEATURE_NOT_CONFIGURED",
    message: "Feature chưa có dữ liệu trong KV."
  }, 404);
}


export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path =
        url.pathname.replace(/\/+$/, "") || "/";

      if (
        path === "/get_mod.php"
      ) {
        return handleGetMod(
          request,
          env,
          ctx
        );
      }

      // Stable Link4m session lifecycle.
      // This bypasses index.js's old cleanup that deleted completed history.
      if (
        request.method === "POST" &&
        path === "/api/link4m/start"
      ) {
        return handleSafeLink4mStart(
          request,
          env
        );
      }

      if (
        request.method === "POST" &&
        path === "/api/link4m/complete"
      ) {
        return forwardAndRecordLink4mComplete(
          request,
          env,
          ctx
        );
      }

      if (
        request.method === "POST" &&
        path === "/api/admin/link4m-stats"
      ) {
        return handleAccurateLink4mStats(request, env);
      }

      if (
        request.method === "POST" &&
        path === "/api/admin/free/create"
      ) {
        return handleAdminFreeCreate(request, env);
      }

      if (
        request.method === "POST" &&
        path === "/api/admin/vip/stats"
      ) {
        return handleAdminVipStats(request, env);
      }

      // Backward-compatible: old admin create route now creates VIP.
      if (
        request.method === "POST" &&
        (
          path === "/api/admin/create-key" ||
          path === "/api/admin/vip/create"
        )
      ) {
        return handleAdminVipCreate(request, env);
      }

      if (
        request.method === "POST" &&
        path === "/api/admin/vip/mark"
      ) {
        return handleAdminMarkVip(request, env);
      }

      // VIP aliases. They rewrite internally so index.js still signs
      // the canonical /api/claim or /api/verify endpoint.
      if (
        request.method === "POST" &&
        path === "/api/vip/claim"
      ) {
        return forwardVipAlias(
          request,
          env,
          ctx,
          "/api/claim"
        );
      }

      if (
        request.method === "POST" &&
        path === "/api/vip/verify"
      ) {
        return forwardVipAlias(
          request,
          env,
          ctx,
          "/api/verify"
        );
      }

      if (
        request.method === "POST" &&
        path === "/api/vip/a"
      ) {
        return forwardVipAlias(
          request,
          env,
          ctx,
          "/a"
        );
      }

      // Existing auth routes:
      // header X-Sent-Product: vip => VIP-only mode.
      // no header                  => FREE-only mode.
      if (
        request.method === "POST" &&
        (
          path === "/api/claim" ||
          path === "/api/verify" ||
          path === "/a"
        )
      ) {
        const requireVip = requestWantsVip(request);

        const gate = await enforceProductGate(
          request,
          env,
          requireVip
        );

        if (!gate.allowed) {
          return gate.response;
        }

        let forwarded = request;

        if (
          path === "/api/claim" ||
          path === "/api/verify"
        ) {
          forwarded = await upgradeLegacyJsonRequest(
            request,
            env
          );
        }

        return signedWorker.fetch(
          forwarded,
          env,
          ctx
        );
      }

      // Public Get Key, Link4m, assets, revoke and all other existing
      // behavior go untouched to index.js.
      return signedWorker.fetch(
        request,
        env,
        ctx
      );
    } catch (error) {
      return json({
        ok: false,
        error:
          error instanceof Error
            ? error.message
            : "Lỗi máy chủ."
      }, 400);
    }
  }
};
