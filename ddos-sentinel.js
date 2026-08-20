// ddos-sentinel.js — Sent Tweaks Sentinel
//
// Fast path: Cloudflare Workers Rate Limiting bindings.
// Persistent state: D1 only for temporary blocks + attack analytics.
// Important: do NOT write one D1 row for every normal request; doing so makes
// the database itself a bottleneck during a flood.

const DEFAULTS = {
  ipLimit: 60,
  ipWindowSeconds: 60,
  burstLimit5s: 15,
  burstLimit10s: 30,
  globalLimit: 5000,
  lockoutSeconds: 300
};

const localWindows = new Map();
const localAlertWindows = new Map();
let lastLocalCleanup = 0;
let lastDbCleanup = 0;

function numberEnv(env, name, fallback, min = 1, max = Number.MAX_SAFE_INTEGER) {
  const value = Number(env?.[name]);
  if (!Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(value)));
}

function enabled(env) {
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

function routeGroup(path) {
  if (path.startsWith("/api/admin/")) return "admin";
  if (path === "/api/claim" || path === "/api/verify" || path === "/a") {
    return "auth";
  }
  if (path.startsWith("/api/link4m/")) return "link4m";
  if (path.startsWith("/api/vip/")) return "vip";
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

async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(String(input));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}

async function clientStorageKey(ip, env) {
  const secret = String(env?.SENTINEL_HASH_SECRET || env?.DEVICE_SALT || "");

  if (!secret) {
    return sha256Hex(`sentinel:${ip}`);
  }

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(ip));
  return Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, "0")).join("");
}

function cleanupLocalMaps(now) {
  if (now - lastLocalCleanup < 60_000) return;
  lastLocalCleanup = now;

  for (const [key, value] of localWindows) {
    if (value.expiresAt <= now) localWindows.delete(key);
  }
  for (const [key, expiresAt] of localAlertWindows) {
    if (expiresAt <= now) localAlertWindows.delete(key);
  }
}

function localLimit(key, limit, periodMs, now = Date.now()) {
  cleanupLocalMaps(now);

  const previous = localWindows.get(key);
  if (!previous || previous.expiresAt <= now) {
    localWindows.set(key, { count: 1, expiresAt: now + periodMs });
    return { success: true, remaining: Math.max(0, limit - 1) };
  }

  previous.count += 1;
  localWindows.set(key, previous);
  return {
    success: previous.count <= limit,
    remaining: Math.max(0, limit - previous.count)
  };
}

async function consume(binding, key, fallbackLimit, fallbackPeriodSeconds) {
  if (binding && typeof binding.limit === "function") {
    try {
      return await binding.limit({ key });
    } catch (error) {
      console.warn("Sentinel rate-limit binding failed; using local fallback", error);
    }
  }

  return localLimit(
    `fallback:${key}`,
    fallbackLimit,
    fallbackPeriodSeconds * 1000
  );
}

async function lookupBlock(env, clientKey, now) {
  if (!env?.DB) return null;

  try {
    return await env.DB.prepare(
      `SELECT reason, expires_at
       FROM sentinel_blocklist
       WHERE client_key = ?
         AND (expires_at IS NULL OR expires_at > ?)
       LIMIT 1`
    ).bind(clientKey, now).first();
  } catch (error) {
    // Migration may not have been applied yet. Fail open so auth does not break.
    console.warn("Sentinel blocklist lookup unavailable", error);
    return null;
  }
}

async function maybeCleanupD1(env, now) {
  if (!env?.DB) return;
  if (now - lastDbCleanup < 60 * 60 * 1000) return;
  lastDbCleanup = now;

  const retentionDays = numberEnv(env, "ATTACK_LOG_RETENTION_DAYS", 7, 1, 90);
  const logCutoff = now - retentionDays * 24 * 60 * 60 * 1000;

  try {
    await env.DB.batch([
      env.DB.prepare(
        `DELETE FROM sentinel_blocklist
         WHERE expires_at IS NOT NULL AND expires_at <= ?`
      ).bind(now),
      env.DB.prepare(
        `DELETE FROM sentinel_attack_logs WHERE timestamp < ?`
      ).bind(logCutoff)
    ]);
  } catch (error) {
    console.warn("Sentinel cleanup failed", error);
  }
}

async function persistAttack(env, event) {
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
    console.warn("Sentinel attack persistence failed", error);
  }
}

async function canSendAlert(env, reason) {
  if (env?.SENTINEL_ALERT_LIMITER && typeof env.SENTINEL_ALERT_LIMITER.limit === "function") {
    try {
      const result = await env.SENTINEL_ALERT_LIMITER.limit({ key: `alert:${reason}` });
      return Boolean(result?.success);
    } catch {}
  }

  const now = Date.now();
  const key = `alert:${reason}`;
  const expiresAt = localAlertWindows.get(key) || 0;
  if (expiresAt > now) return false;
  localAlertWindows.set(key, now + 60_000);
  return true;
}

async function sendAlert(env, event) {
  const botToken = String(env?.TELEGRAM_BOT_TOKEN || "");
  const chatId = String(env?.TELEGRAM_CHAT_ID || "");
  if (!botToken || !chatId) return;
  if (!(await canSendAlert(env, event.reason))) return;

  const safeIp = event.ip === "unknown" ? "unknown" : event.ip.replace(/`/g, "");
  const text = [
    "🚨 SENTINEL ALERT",
    `Reason: ${event.reason}`,
    `IP: ${safeIp}`,
    `Path: ${event.path}`,
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

async function reportViolation(request, env, ctx, clientKey, reason, blockSeconds = 0) {
  const now = Date.now();
  const url = new URL(request.url);
  const event = {
    now,
    reason,
    blockSeconds,
    clientKey,
    ip: getClientIP(request),
    userAgent: request.headers.get("user-agent") || "",
    path: url.pathname,
    cfRay: request.headers.get("cf-ray") || "",
    country: String(request.cf?.country || "")
  };

  const work = Promise.allSettled([
    persistAttack(env, event),
    sendAlert(env, event),
    maybeCleanupD1(env, now)
  ]);

  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(work);
  } else {
    await work;
  }
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
  if (!enabled(env)) return { allowed: true };

  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  if (!shouldProtect(request, path)) return { allowed: true };

  const now = Date.now();
  const ip = getClientIP(request);
  const clientKey = await clientStorageKey(ip, env);
  const group = routeGroup(path);
  const colo = String(request.cf?.colo || "unknown");

  const globalLimit = numberEnv(env, "GLOBAL_RATE_LIMIT", DEFAULTS.globalLimit, 100, 1000000);
  const global = await consume(
    env?.SENTINEL_GLOBAL_LIMITER,
    `global:${colo}`,
    globalLimit,
    60
  );

  if (!global?.success) {
    await reportViolation(request, env, ctx, clientKey, "SYSTEM_OVERLOAD", 0);
    return deny(503, "SYSTEM_OVERLOAD", "Hệ thống đang quá tải, vui lòng thử lại sau.", 60);
  }

  const ipLimit = numberEnv(env, "RATE_LIMIT_PER_IP", DEFAULTS.ipLimit, 5, 10000);
  const ipWindow = numberEnv(env, "RATE_LIMIT_WINDOW", DEFAULTS.ipWindowSeconds, 10, 60);
  const perIp = await consume(
    env?.SENTINEL_API_LIMITER,
    `${clientKey}:${group}`,
    ipLimit,
    ipWindow
  );

  if (!perIp?.success) {
    await reportViolation(request, env, ctx, clientKey, "RATE_LIMIT_EXCEEDED", 0);
    return deny(429, "RATE_LIMIT_EXCEEDED", "Quá nhiều yêu cầu. Vui lòng thử lại sau.", ipWindow);
  }

  // Exact 5-second local burst guard. This is isolate-local by design, so the
  // Cloudflare 10-second binding below remains the distributed fast-path guard.
  const burst5 = numberEnv(env, "BURST_THRESHOLD", DEFAULTS.burstLimit5s, 3, 1000);
  const localBurst = localLimit(`burst5:${clientKey}:${group}`, burst5, 5000, now);

  const burst10 = await consume(
    env?.SENTINEL_BURST_LIMITER,
    `${clientKey}:${group}`,
    DEFAULTS.burstLimit10s,
    10
  );

  if (!localBurst.success || !burst10?.success) {
    const lockout = numberEnv(env, "LOCKOUT_SECONDS", DEFAULTS.lockoutSeconds, 30, 86400);
    await reportViolation(request, env, ctx, clientKey, "BURST_DETECTED", lockout);
    return deny(403, "BURST_DETECTED", "Phát hiện đột biến request. Truy cập đã bị khóa tạm thời.", lockout);
  }

  const blocked = await lookupBlock(env, clientKey, now);
  if (blocked) {
    const retryAfter = blocked.expires_at
      ? Math.max(1, Math.ceil((Number(blocked.expires_at) - now) / 1000))
      : 3600;

    return deny(
      403,
      "CLIENT_BLOCKED",
      "Truy cập đã bị chặn tạm thời do hoạt động bất thường.",
      retryAfter
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
