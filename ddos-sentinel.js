// ddos-sentinel.js — Sent Tweaks Sentinel V2
//
// Goals:
// - Keep FREE/VIP/Link4m/auth/get_mod behavior unchanged.
// - Do not use D1 on the normal request fast path.
// - Use Workers Rate Limiting bindings for counters.
// - Keep only bounded, isolate-local penalty/fallback state in memory.
// - Persist sampled security events to D1 only after a violation.
// - Never force browser challenges on native/API routes.

const DEFAULTS = Object.freeze({
  globalLimit: 5000,
  apiLimit: 120,
  authLimit: 60,
  link4mLimit: 30,
  adminLimit: 10,
  featureLimit: 180,
  callbackLimit: 120,
  burstLimit10s: 30,
  burstFallback5s: 15,
  penaltySeconds: 300,
  maxBodyBytes: 64 * 1024,
  maxLocalEntries: 12000,
  retentionDays: 7
});

const localWindows = new Map();
const localPenalties = new Map();
const localAlerts = new Map();
let lastLocalCleanup = 0;
let lastDbCleanup = 0;
let cachedHmacSecret = null;
let cachedHmacKeyPromise = null;

function intEnv(env, name, fallback, min = 1, max = Number.MAX_SAFE_INTEGER) {
  const value = Number(env?.[name]);
  if (!Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(value)));
}

function isEnabled(env) {
  return String(env?.SENTINEL_ENABLED ?? "true").toLowerCase() !== "false";
}

export function getClientIP(request) {
  return (
    request.headers.get("cf-connecting-ip") ||
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    request.headers.get("x-real-ip") ||
    "unknown"
  );
}

function normalizePath(url) {
  return url.pathname.replace(/\/+$/, "") || "/";
}

function routeGroup(path) {
  if (path.startsWith("/api/admin/")) return "admin";

  if (
    path === "/api/claim" ||
    path === "/api/verify" ||
    path === "/a" ||
    path === "/auth" ||
    path === "/login" ||
    path === "/verify" ||
    path === "/check" ||
    path.startsWith("/license/") ||
    path === "/api/vip/claim" ||
    path === "/api/vip/verify" ||
    path === "/api/vip/a"
  ) {
    return "auth";
  }

  if (path.startsWith("/api/link4m/")) return "link4m";
  if (path === "/get_mod.php") return "feature";
  if (path === "/senttwgetkey" || path === "/senttwnhankey") return "callback";
  if (path.startsWith("/api/")) return "api";
  return "dynamic";
}

function shouldProtect(request, path) {
  if (request.method === "OPTIONS") return false;

  return (
    path.startsWith("/api/") ||
    path === "/a" ||
    path === "/auth" ||
    path === "/login" ||
    path === "/verify" ||
    path === "/check" ||
    path.startsWith("/license/") ||
    path === "/get_mod.php" ||
    path === "/senttwgetkey" ||
    path === "/senttwnhankey"
  );
}

function policyFor(group, env) {
  switch (group) {
    case "admin":
      return {
        binding: env?.SENTINEL_ADMIN_LIMITER,
        limit: intEnv(env, "SENTINEL_ADMIN_FALLBACK_LIMIT", DEFAULTS.adminLimit, 2, 1000),
        period: 60
      };
    case "auth":
      return {
        binding: env?.SENTINEL_AUTH_LIMITER,
        limit: intEnv(env, "SENTINEL_AUTH_FALLBACK_LIMIT", DEFAULTS.authLimit, 5, 5000),
        period: 60
      };
    case "link4m":
      return {
        binding: env?.SENTINEL_LINK4M_LIMITER,
        limit: intEnv(env, "SENTINEL_LINK4M_FALLBACK_LIMIT", DEFAULTS.link4mLimit, 5, 5000),
        period: 60
      };
    case "feature":
      return {
        binding: env?.SENTINEL_FEATURE_LIMITER || env?.SENTINEL_API_LIMITER,
        limit: intEnv(env, "SENTINEL_FEATURE_FALLBACK_LIMIT", DEFAULTS.featureLimit, 10, 10000),
        period: 60
      };
    case "callback":
      return {
        binding: env?.SENTINEL_CALLBACK_LIMITER || env?.SENTINEL_API_LIMITER,
        limit: intEnv(env, "SENTINEL_CALLBACK_FALLBACK_LIMIT", DEFAULTS.callbackLimit, 10, 10000),
        period: 60
      };
    default:
      return {
        binding: env?.SENTINEL_API_LIMITER,
        limit: intEnv(env, "SENTINEL_API_FALLBACK_LIMIT", DEFAULTS.apiLimit, 10, 10000),
        period: 60
      };
  }
}

function deleteOldestEntries(map, count) {
  if (count <= 0) return;
  let removed = 0;
  for (const key of map.keys()) {
    map.delete(key);
    removed += 1;
    if (removed >= count) break;
  }
}

function enforceLocalCap(map, maxEntries) {
  if (map.size < maxEntries) return;
  const removeCount = Math.max(1, Math.ceil(maxEntries * 0.2));
  deleteOldestEntries(map, removeCount);
}

function cleanupLocalState(now, maxEntries) {
  if (now - lastLocalCleanup < 10_000) return;
  lastLocalCleanup = now;

  for (const [key, value] of localWindows) {
    if (!value || value.expiresAt <= now) localWindows.delete(key);
  }
  for (const [key, expiresAt] of localPenalties) {
    if (!expiresAt || expiresAt <= now) localPenalties.delete(key);
  }
  for (const [key, expiresAt] of localAlerts) {
    if (!expiresAt || expiresAt <= now) localAlerts.delete(key);
  }

  if (localWindows.size > maxEntries) {
    deleteOldestEntries(localWindows, localWindows.size - maxEntries);
  }
  if (localPenalties.size > maxEntries) {
    deleteOldestEntries(localPenalties, localPenalties.size - maxEntries);
  }
  if (localAlerts.size > Math.min(maxEntries, 2000)) {
    deleteOldestEntries(localAlerts, localAlerts.size - Math.min(maxEntries, 2000));
  }
}

function localLimit(key, limit, periodMs, now, maxEntries) {
  cleanupLocalState(now, maxEntries);

  const previous = localWindows.get(key);
  if (!previous || previous.expiresAt <= now) {
    enforceLocalCap(localWindows, maxEntries);
    localWindows.set(key, { count: 1, expiresAt: now + periodMs });
    return { success: true, remaining: Math.max(0, limit - 1), local: true };
  }

  previous.count += 1;
  // Refresh insertion order only when the entry is actively used.
  localWindows.delete(key);
  localWindows.set(key, previous);

  return {
    success: previous.count <= limit,
    remaining: Math.max(0, limit - previous.count),
    local: true
  };
}

async function consume(binding, key, fallbackLimit, fallbackPeriodSeconds, now, maxEntries) {
  if (binding && typeof binding.limit === "function") {
    try {
      const result = await binding.limit({ key });
      if (result && typeof result.success === "boolean") return result;
    } catch (error) {
      console.warn("Sentinel limiter binding unavailable; local fallback enabled", error);
    }
  }

  return localLimit(
    `fallback:${key}`,
    fallbackLimit,
    fallbackPeriodSeconds * 1000,
    now,
    maxEntries
  );
}

function setPenalty(key, seconds, now, maxEntries) {
  enforceLocalCap(localPenalties, maxEntries);
  localPenalties.set(key, now + seconds * 1000);
}

function getPenaltySeconds(key, now) {
  const expiresAt = localPenalties.get(key) || 0;
  if (expiresAt <= now) {
    if (expiresAt) localPenalties.delete(key);
    return 0;
  }
  return Math.max(1, Math.ceil((expiresAt - now) / 1000));
}

function declaredBodyTooLarge(request, maxBodyBytes) {
  const method = request.method.toUpperCase();
  if (!new Set(["POST", "PUT", "PATCH", "DELETE"]).has(method)) return false;

  const value = request.headers.get("content-length");
  if (!value) return false;

  const length = Number(value);
  return Number.isFinite(length) && length > maxBodyBytes;
}

async function getHmacKey(secret) {
  if (cachedHmacSecret !== secret || !cachedHmacKeyPromise) {
    cachedHmacSecret = secret;
    cachedHmacKeyPromise = crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
  }
  return cachedHmacKeyPromise;
}

async function clientStorageKey(ip, env) {
  const secret = String(env?.SENTINEL_HASH_SECRET || env?.DEVICE_SALT || "sentinel-v2");
  const key = await getHmacKey(secret);
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(String(ip))
  );
  return Array.from(new Uint8Array(sig), byte => byte.toString(16).padStart(2, "0")).join("");
}

async function maybeCleanupD1(env, now) {
  if (!env?.DB) return;
  if (now - lastDbCleanup < 60 * 60 * 1000) return;
  lastDbCleanup = now;

  const retentionDays = intEnv(env, "ATTACK_LOG_RETENTION_DAYS", DEFAULTS.retentionDays, 1, 90);
  const cutoff = now - retentionDays * 24 * 60 * 60 * 1000;

  try {
    await env.DB.batch([
      env.DB.prepare(
        `DELETE FROM sentinel_blocklist
         WHERE expires_at IS NOT NULL AND expires_at <= ?`
      ).bind(now),
      env.DB.prepare(
        `DELETE FROM sentinel_attack_logs WHERE timestamp < ?`
      ).bind(cutoff)
    ]);
  } catch (error) {
    console.warn("Sentinel D1 cleanup failed", error);
  }
}

async function canPersistViolation(env, rawKey, reason, now, maxEntries) {
  if (env?.SENTINEL_LOG_LIMITER && typeof env.SENTINEL_LOG_LIMITER.limit === "function") {
    try {
      const result = await env.SENTINEL_LOG_LIMITER.limit({ key: `${rawKey}:${reason}` });
      return Boolean(result?.success);
    } catch (error) {
      console.warn("Sentinel log limiter unavailable", error);
    }
  }

  const fallback = localLimit(
    `log:${rawKey}:${reason}`,
    1,
    60_000,
    now,
    Math.min(maxEntries, 4000)
  );
  return fallback.success;
}

async function persistViolation(env, event) {
  if (!env?.DB) return;

  try {
    const statements = [
      env.DB.prepare(
        `INSERT INTO sentinel_attack_logs
          (client_key, reason, timestamp, user_agent, path, cf_ray, country)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        event.clientKey,
        event.reason,
        event.now,
        event.userAgent.slice(0, 300),
        event.path.slice(0, 300),
        event.cfRay.slice(0, 100),
        event.country.slice(0, 16)
      )
    ];

    if (event.blockSeconds > 0) {
      statements.push(
        env.DB.prepare(
          `INSERT INTO sentinel_blocklist
            (client_key, reason, blocked_at, expires_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(client_key) DO UPDATE SET
             reason = excluded.reason,
             blocked_at = excluded.blocked_at,
             expires_at = MAX(COALESCE(sentinel_blocklist.expires_at, 0), excluded.expires_at)`
        ).bind(
          event.clientKey,
          event.reason,
          event.now,
          event.now + event.blockSeconds * 1000
        )
      );
    }

    await env.DB.batch(statements);
  } catch (error) {
    // Fail open: security analytics must never break key/login functionality.
    console.warn("Sentinel security log persistence failed", error);
  }
}

async function canSendAlert(env, reason, now) {
  if (env?.SENTINEL_ALERT_LIMITER && typeof env.SENTINEL_ALERT_LIMITER.limit === "function") {
    try {
      const result = await env.SENTINEL_ALERT_LIMITER.limit({ key: `alert:${reason}` });
      return Boolean(result?.success);
    } catch {}
  }

  const key = `alert:${reason}`;
  const expiresAt = localAlerts.get(key) || 0;
  if (expiresAt > now) return false;
  localAlerts.set(key, now + 60_000);
  return true;
}

async function sendAlert(env, event) {
  const botToken = String(env?.TELEGRAM_BOT_TOKEN || "");
  const chatId = String(env?.TELEGRAM_CHAT_ID || "");
  if (!botToken || !chatId) return;
  if (!(await canSendAlert(env, event.reason, event.now))) return;

  const text = [
    "🚨 SENTINEL V2",
    `Reason: ${event.reason}`,
    `Path: ${event.path}`,
    `Country: ${event.country || "n/a"}`,
    `Ray: ${event.cfRay || "n/a"}`,
    `Time: ${new Date(event.now).toISOString()}`
  ].join("\n");

  try {
    await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text })
    });
  } catch (error) {
    console.warn("Sentinel Telegram alert failed", error);
  }
}

async function reportViolation(request, env, reason, blockSeconds, rawKey, maxEntries) {
  const now = Date.now();

  if (!(await canPersistViolation(env, rawKey, reason, now, maxEntries))) {
    return;
  }

  const url = new URL(request.url);
  const clientKey = await clientStorageKey(getClientIP(request), env);
  const event = {
    now,
    reason,
    blockSeconds,
    clientKey,
    userAgent: request.headers.get("user-agent") || "",
    path: normalizePath(url),
    cfRay: request.headers.get("cf-ray") || "",
    country: String(request.cf?.country || "")
  };

  await Promise.allSettled([
    persistViolation(env, event),
    sendAlert(env, event),
    maybeCleanupD1(env, now)
  ]);
}

function queueViolation(request, env, ctx, reason, blockSeconds, rawKey, maxEntries) {
  const work = reportViolation(request, env, reason, blockSeconds, rawKey, maxEntries);
  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(work);
    return;
  }
  return work;
}

function deny(status, error, message, retryAfter = 0) {
  return {
    allowed: false,
    status,
    error,
    message,
    retryAfter
  };
}

export async function validateRequest(request, env, ctx) {
  if (!isEnabled(env)) return { allowed: true };

  const url = new URL(request.url);
  const path = normalizePath(url);
  if (!shouldProtect(request, path)) return { allowed: true };

  const now = Date.now();
  const maxEntries = intEnv(env, "SENTINEL_LOCAL_STATE_MAX", DEFAULTS.maxLocalEntries, 1000, 50000);
  cleanupLocalState(now, maxEntries);

  const ip = getClientIP(request);
  const group = routeGroup(path);
  // Raw IP is used only as an ephemeral limiter key inside Cloudflare/local memory.
  // It is never written to D1 security logs.
  const actorKey = `${ip}:${group}`;

  const penaltySeconds = getPenaltySeconds(actorKey, now);
  if (penaltySeconds > 0) {
    return deny(
      429,
      "TEMPORARY_THROTTLE",
      "Truy cập đang bị giới hạn tạm thời do tần suất bất thường.",
      penaltySeconds
    );
  }

  const maxBodyBytes = intEnv(env, "SENTINEL_MAX_BODY_BYTES", DEFAULTS.maxBodyBytes, 4096, 1024 * 1024);
  if (declaredBodyTooLarge(request, maxBodyBytes)) {
    queueViolation(request, env, ctx, "BODY_TOO_LARGE", 0, actorKey, maxEntries);
    return deny(
      413,
      "BODY_TOO_LARGE",
      "Dữ liệu gửi lên vượt quá giới hạn cho phép.",
      0
    );
  }

  const colo = String(request.cf?.colo || "unknown");
  const globalLimit = intEnv(env, "GLOBAL_RATE_LIMIT", DEFAULTS.globalLimit, 100, 1000000);
  const globalResult = await consume(
    env?.SENTINEL_GLOBAL_LIMITER,
    `global:${colo}`,
    globalLimit,
    60,
    now,
    maxEntries
  );

  if (!globalResult?.success) {
    queueViolation(request, env, ctx, "SYSTEM_OVERLOAD", 0, actorKey, maxEntries);
    return deny(503, "SYSTEM_OVERLOAD", "Hệ thống đang quá tải, vui lòng thử lại sau.", 60);
  }

  const policy = policyFor(group, env);
  const perActor = await consume(
    policy.binding,
    actorKey,
    policy.limit,
    policy.period,
    now,
    maxEntries
  );

  if (!perActor?.success) {
    queueViolation(request, env, ctx, `RATE_LIMIT_${group.toUpperCase()}`, 0, actorKey, maxEntries);
    return deny(429, "RATE_LIMIT_EXCEEDED", "Quá nhiều yêu cầu. Vui lòng thử lại sau.", policy.period);
  }

  // Prefer Cloudflare's distributed 10-second limiter. The exact 5-second
  // Map-based guard is used ONLY if the binding is unavailable, preventing
  // attacker-controlled IP churn from growing local state during normal prod.
  let burstAllowed = true;
  if (env?.SENTINEL_BURST_LIMITER && typeof env.SENTINEL_BURST_LIMITER.limit === "function") {
    const burstResult = await consume(
      env.SENTINEL_BURST_LIMITER,
      actorKey,
      DEFAULTS.burstLimit10s,
      10,
      now,
      maxEntries
    );
    burstAllowed = Boolean(burstResult?.success);
  } else {
    const burst5Limit = intEnv(env, "BURST_THRESHOLD", DEFAULTS.burstFallback5s, 3, 1000);
    const burst5 = localLimit(
      `burst5:${actorKey}`,
      burst5Limit,
      5000,
      now,
      maxEntries
    );
    burstAllowed = burst5.success;
  }

  if (!burstAllowed) {
    const blockSeconds = intEnv(env, "LOCKOUT_SECONDS", DEFAULTS.penaltySeconds, 30, 3600);
    setPenalty(actorKey, blockSeconds, now, maxEntries);
    queueViolation(request, env, ctx, "BURST_DETECTED", blockSeconds, actorKey, maxEntries);
    return deny(
      429,
      "BURST_DETECTED",
      "Phát hiện đột biến request. Truy cập đã bị giới hạn tạm thời.",
      blockSeconds
    );
  }

  return { allowed: true };
}

export function sentinelResponse(result) {
  const headers = new Headers({
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()"
  });

  if (result.retryAfter) {
    headers.set("retry-after", String(result.retryAfter));
  }

  return new Response(JSON.stringify({
    ok: false,
    error: result.error,
    message: result.message
  }), {
    status: result.status || 429,
    headers
  });
}
