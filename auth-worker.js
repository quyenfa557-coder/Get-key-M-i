// Sent Tweaks compatibility entry.
// It upgrades older JSON clients to the signed Auth V4 request shape,
// then delegates all real validation to index.js (D1, expiry, device binding, signatures).
import signedWorker from "./index.js";

const AUTH_PROTOCOL_VERSION = 4;
const DEFAULT_BUILD_ID = "sent-menu-2026.08.07-r1";
const DEFAULT_CLIENT_VERSION = "5.2.1";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    }
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

  // Do not alter a complete Auth V4 request.
  if (looksLikeModernV4(body)) {
    return request;
  }

  const key = firstString(body, [
    "key",
    "licenseKey",
    "license_key",
    "userKey",
    "user_key",
    "code"
  ]);

  const deviceId = firstString(body, [
    "deviceId",
    "device_id",
    "stableDeviceId",
    "stable_device_id",
    "androidId",
    "android_id",
    "device"
  ]);

  // Let index.js return the normal structured error for truly malformed requests.
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
    buildId: String(
      env.AUTH_ACTIVE_BUILD_ID || DEFAULT_BUILD_ID
    ),
    clientVersion: String(
      env.AUTH_CLIENT_VERSION || DEFAULT_CLIENT_VERSION
    )
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

/*
 * ==========================================================
 * LINK4M ANALYTICS V2
 * ==========================================================
 * - Counts only completed Link4m sessions that have a license key.
 * - Admin-created keys are excluded automatically because they have no
 *   matching completed link_sessions row.
 * - "Today" and "Yesterday" use fixed Vietnam time (UTC+7), independent
 *   of the browser/device timezone.
 * - No schema migration is required.
 */

const VN_OFFSET_MS = 7 * 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const MULTI_DEVICE_PREFIX = "SENTMULTI:v1:";

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

function mapRecentLink4mRow(row, now) {
  const expiresAt = Number(row.expires_at);
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
      Number(row.completed_at || row.created_at || now)
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
    status
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

  const now = Date.now();
  const {
    yesterdayStart,
    todayStart,
    tomorrowStart
  } = vietnamDayBounds(now);

  /*
   * COUNT(*) = number of successful completed Link4m sessions.
   * COUNT(DISTINCT license_key) = number of distinct keys produced by Link4m.
   *
   * We intentionally do not call this "unique people" because the current
   * database does not store a stable user identity. Calling sessions "people"
   * would make the dashboard inaccurate.
   */
  const summary = await env.DB.prepare(
    `SELECT
       COUNT(*) AS completed_sessions,
       COUNT(DISTINCT ls.license_key) AS total,
       COUNT(DISTINCT CASE
         WHEN ls.completed_at >= ? AND ls.completed_at < ?
         THEN ls.license_key
       END) AS today,
       COUNT(DISTINCT CASE
         WHEN ls.completed_at >= ? AND ls.completed_at < ?
         THEN ls.license_key
       END) AS yesterday,
       COUNT(DISTINCT CASE
         WHEN k.status = 'active' AND k.expires_at > ?
         THEN ls.license_key
       END) AS active,
       COUNT(DISTINCT CASE
         WHEN k.status != 'revoked' AND k.expires_at <= ?
         THEN ls.license_key
       END) AS expired,
       COUNT(DISTINCT CASE
         WHEN k.status = 'revoked'
         THEN ls.license_key
       END) AS revoked
     FROM link_sessions AS ls
     LEFT JOIN keys AS k
       ON k.license_key = ls.license_key
     WHERE ls.completed_at IS NOT NULL
       AND ls.license_key IS NOT NULL`
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
       ls.license_key,
       MAX(ls.completed_at) AS completed_at,
       k.plan_hours,
       k.device_hash,
       k.claimed_at,
       k.created_at,
       k.expires_at,
       k.status
     FROM link_sessions AS ls
     INNER JOIN keys AS k
       ON k.license_key = ls.license_key
     WHERE ls.completed_at IS NOT NULL
       AND ls.license_key IS NOT NULL
     GROUP BY ls.license_key
     ORDER BY completed_at DESC
     LIMIT 20`
  ).all();

  const recent = (recentResult.results || []).map(
    row => mapRecentLink4mRow(row, now)
  );

  const today = Number(summary?.today || 0);
  const yesterday = Number(summary?.yesterday || 0);
  const difference = today - yesterday;

  let percentChange = null;
  if (yesterday > 0) {
    percentChange = Math.round((difference / yesterday) * 10000) / 100;
  } else if (today > 0) {
    percentChange = 100;
  } else {
    percentChange = 0;
  }

  return json({
    ok: true,
    generatedAt: new Date(now).toISOString(),
    timeZone: "Asia/Ho_Chi_Minh",
    dayBounds: {
      yesterdayStart: new Date(yesterdayStart).toISOString(),
      todayStart: new Date(todayStart).toISOString(),
      tomorrowStart: new Date(tomorrowStart).toISOString()
    },
    stats: {
      completedSessions: Number(summary?.completed_sessions || 0),
      total: Number(summary?.total || 0),
      today,
      yesterday,
      active: Number(summary?.active || 0),
      expired: Number(summary?.expired || 0),
      revoked: Number(summary?.revoked || 0),
      todayVsYesterday: {
        difference,
        percentChange
      }
    },
    recent
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    // Analytics V2 intercept: no change to index.js is required.
    if (
      request.method === "POST" &&
      path === "/api/admin/link4m-stats"
    ) {
      return handleAccurateLink4mStats(request, env);
    }

    let forwarded = request;

    if (
      request.method === "POST" &&
      (path === "/api/claim" || path === "/api/verify")
    ) {
      forwarded = await upgradeLegacyJsonRequest(request, env);
    }

    return signedWorker.fetch(forwarded, env, ctx);
  }
};
