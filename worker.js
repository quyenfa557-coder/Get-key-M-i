export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (error) {
      return json(
        {
          ok: false,
          valid: false,
          error: "INTERNAL_ERROR",
          detail: String(error?.message || error)
        },
        500
      );
    }
  }
};

const CLAIM_PATHS = new Set([
  "/api/claim",
  "/auth",
  "/login",
  "/license/claim"
]);

const VERIFY_PATHS = new Set([
  "/api/verify",
  "/verify",
  "/license/verify"
]);

async function route(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders()
    });
  }

  if (path === "/") {
    return json({
      ok: true,
      service: "Sent Tweaks Auth",
      endpoints: {
        claim: [...CLAIM_PATHS],
        verify: [...VERIFY_PATHS]
      }
    });
  }

  if (CLAIM_PATHS.has(path)) {
    return handleAuth(request, env, true);
  }

  if (VERIFY_PATHS.has(path)) {
    return handleAuth(request, env, false);
  }

  return json(
    {
      ok: false,
      valid: false,
      error: "NOT_FOUND"
    },
    404
  );
}

async function handleAuth(request, env, bindOnSuccess) {
  if (!["GET", "POST"].includes(request.method)) {
    return json(
      {
        ok: false,
        valid: false,
        error: "METHOD_NOT_ALLOWED"
      },
      405
    );
  }

  const data = await readFlexibleInput(request);

  const licenseKey = firstString(data, [
    "key",
    "licenseKey",
    "license_key",
    "userKey",
    "user_key",
    "code"
  ]);

  const deviceId = firstString(data, [
    "deviceId",
    "device_id",
    "androidId",
    "android_id",
    "stableDeviceId",
    "stable_device_id",
    "device"
  ]);

  if (!licenseKey) {
    return json(
      {
        ok: false,
        valid: false,
        error: "MISSING_KEY"
      },
      400
    );
  }

  if (!deviceId) {
    return json(
      {
        ok: false,
        valid: false,
        error: "MISSING_DEVICE_ID"
      },
      400
    );
  }

  const now = Math.floor(Date.now() / 1000);

  const row = await env.DB.prepare(
    `
    SELECT
      license_key,
      status,
      expires_at,
      device_bound,
      used,
      max_uses,
      last_used_at
    FROM keys
    WHERE license_key = ?
    LIMIT 1
    `
  )
    .bind(licenseKey)
    .first();

  if (!row) {
    return authFailure("INVALID_KEY", 401);
  }

  if (String(row.status || "").toLowerCase() !== "active") {
    return authFailure("KEY_INACTIVE", 403);
  }

  if (Number(row.expires_at || 0) <= now) {
    return authFailure("KEY_EXPIRED", 403);
  }

  const currentDevice = String(row.device_bound || "").trim();

  if (currentDevice && currentDevice !== deviceId) {
    return authFailure("DEVICE_MISMATCH", 403);
  }

  const currentUses = Number(row.used || 0);
  const maxUses = Number(row.max_uses || 1);

  if (currentUses >= maxUses && currentDevice !== deviceId) {
    return authFailure("KEY_ALREADY_USED", 403);
  }

  if (bindOnSuccess) {
    await env.DB.batch([
      env.DB.prepare(
        `
        UPDATE keys
        SET
          device_bound = COALESCE(NULLIF(device_bound, ''), ?),
          used = CASE
            WHEN device_bound IS NULL OR device_bound = '' THEN used + 1
            ELSE used
          END,
          last_used_at = ?
        WHERE license_key = ?
        `
      ).bind(deviceId, now, licenseKey),

      env.DB.prepare(
        `
        INSERT INTO link_sessions (
          session_hash,
          license_key,
          device_id,
          created_at,
          expires_at,
          completed_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        `
      ).bind(
        crypto.randomUUID(),
        licenseKey,
        deviceId,
        now,
        Number(row.expires_at),
        now
      )
    ]);
  }

  const response = {
    ok: true,
    valid: true,
    success: true,
    status: "success",
    message: "AUTHENTICATION_SUCCESS",
    data: {
      key: licenseKey,
      licenseKey,
      deviceId,
      device_id: deviceId,
      expiresAt: Number(row.expires_at),
      expires_at: Number(row.expires_at),
      remainingSeconds: Math.max(0, Number(row.expires_at) - now)
    }
  };

  return json(response, 200);
}

function authFailure(reason, status) {
  return json(
    {
      ok: false,
      valid: false,
      success: false,
      status: "error",
      error: reason,
      message: reason
    },
    status
  );
}

async function readFlexibleInput(request) {
  const url = new URL(request.url);
  const query = Object.fromEntries(url.searchParams.entries());

  if (request.method === "GET") {
    return query;
  }

  const contentType = String(
    request.headers.get("content-type") || ""
  ).toLowerCase();

  const raw = await request.text();

  if (!raw.trim()) {
    return query;
  }

  let body = {};

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

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("REQUEST_BODY_NOT_OBJECT");
  }

  return {
    ...query,
    ...body
  };
}

function firstString(source, names) {
  for (const name of names) {
    const value = source?.[name];

    if (
      typeof value === "string" &&
      value.trim()
    ) {
      return value.trim();
    }
  }

  return "";
}

function json(payload, status = 200) {
  const headers = corsHeaders();
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");

  return new Response(JSON.stringify(payload), {
    status,
    headers
  });
}

function corsHeaders() {
  return new Headers({
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization, x-api-key"
  });
}
