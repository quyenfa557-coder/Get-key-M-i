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

function redirect(location, status = 302) {
  return new Response(null, {
    status,
    headers: {
      location,
      "cache-control": "no-store"
    }
  });
}

async function readJson(request) {
  const type = request.headers.get("content-type") || "";

  if (!type.includes("application/json")) {
    throw new Error("Yêu cầu phải là JSON.");
  }

  return request.json();
}

function normalizeDeviceId(value) {
  const id = String(value || "").trim();

  if (id.length < 6 || id.length > 200) {
    throw new Error("Device ID phải có từ 6 đến 200 ký tự.");
  }

  return id;
}

function normalizePlan(value) {
  const plan = Number(value);

  if (plan !== 12 && plan !== 24) {
    throw new Error("Gói key chỉ hỗ trợ 12 hoặc 24 giờ.");
  }

  return plan;
}

function normalizeKey(value) {
  const key = String(value || "").trim().toUpperCase();

  if (!/^SENT-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(key)) {
    throw new Error("Key không đúng định dạng.");
  }

  return key;
}

function normalizeSessionToken(value) {
  const token = String(value || "").trim();

  if (!/^[A-Za-z0-9_-]{40,100}$/.test(token)) {
    throw new Error("Mã phiên Link4m không hợp lệ.");
  }

  return token;
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

function createKey() {
  return `SENT-${randomPart()}-${randomPart()}-${randomPart()}`;
}

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

async function sha256(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(
    new Uint8Array(digest),
    byte => byte.toString(16).padStart(2, "0")
  ).join("");
}

async function deviceHash(env, deviceId) {
  const salt =
    env.DEVICE_SALT ||
    "senttweaks-default-salt-change-me";

  return sha256(`${salt}:${deviceId}`);
}

function publicKeyRow(row, now = Date.now()) {
  const createdAt = Number(row.created_at);
  const claimedAt = row.claimed_at
    ? Number(row.claimed_at)
    : null;

  const expiresAt = Number(row.expires_at);
  const expired = now >= expiresAt;

  return {
    key: row.license_key,
    planHours: Number(row.plan_hours),
    bound: Boolean(row.device_hash),

    createdAt: new Date(createdAt).toISOString(),

    claimedAt: claimedAt
      ? new Date(claimedAt).toISOString()
      : null,

    expiresAt: new Date(expiresAt).toISOString(),

    remainingSeconds: Math.max(
      0,
      Math.floor((expiresAt - now) / 1000)
    ),

    status:
      row.status === "revoked"
        ? "revoked"
        : expired
          ? "expired"
          : "active"
  };
}

async function insertUniqueKey(env, planHours) {
  const now = Date.now();
  const expiresAt =
    now + planHours * 60 * 60 * 1000;

  for (let attempt = 0; attempt < 5; attempt++) {
    const licenseKey = createKey();

    try {
      await env.DB.prepare(
        `INSERT INTO keys (
          license_key,
          plan_hours,
          created_at,
          expires_at,
          status
        )
        VALUES (?, ?, ?, ?, 'active')`
      )
        .bind(
          licenseKey,
          planHours,
          now,
          expiresAt
        )
        .run();

      return {
        license_key: licenseKey,
        plan_hours: planHours,
        device_hash: null,
        created_at: now,
        claimed_at: null,
        expires_at: expiresAt,
        status: "active"
      };
    } catch (error) {
      const message = String(error).toLowerCase();

      if (!message.includes("unique")) {
        throw error;
      }
    }
  }

  throw new Error("Không thể tạo key mới. Hãy thử lại.");
}

function isAdmin(request, env) {
  const expected = String(env.ADMIN_TOKEN || "");

  return Boolean(expected) &&
    request.headers.get("authorization") ===
      `Bearer ${expected}`;
}

async function handleAdminCreateKey(request, env) {
  if (!isAdmin(request, env)) {
    return json(
      {
        ok: false,
        error: "Không có quyền tạo key."
      },
      401
    );
  }

  const body = await readJson(request);
  const planHours = normalizePlan(body.planHours);

  const row = await insertUniqueKey(
    env,
    planHours
  );

  return json(
    {
      ok: true,
      data: publicKeyRow(row)
    },
    201
  );
}

async function handleLink4mStart(request, env) {
  const apiToken = String(
    env.LINK4M_API_TOKEN || ""
  ).trim();

  if (!apiToken) {
    return json(
      {
        ok: false,
        error: "Máy chủ chưa cấu hình LINK4M_API_TOKEN."
      },
      503
    );
  }

  const now = Date.now();
  const expiresAt = now + 20 * 60 * 1000;

  const sessionToken = randomToken(32);
  const sessionHash = await sha256(sessionToken);

  await env.DB.prepare(
    `DELETE FROM link_sessions
     WHERE expires_at < ?`
  )
    .bind(now - 24 * 60 * 60 * 1000)
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

  const callbackUrl = new URL(
    "/senttwgetkey",
    request.url
  );

  callbackUrl.searchParams.set(
    "session",
    sessionToken
  );

  const link4mApi = new URL(
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
    const response = await fetch(
      link4mApi.toString(),
      {
        method: "GET",
        headers: {
          accept: "application/json"
        }
      }
    );

    const raw = await response.text();

    let result;

    try {
      result = JSON.parse(raw);
    } catch {
      throw new Error(
        "Link4m trả về dữ liệu không hợp lệ."
      );
    }

    if (
      !response.ok ||
      String(result.status || "").toLowerCase() !== "success"
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
       WHERE session_hash = ?`
    )
      .bind(sessionHash)
      .run();

    throw error;
  }
}

function handleLink4mLanding(request) {
  const url = new URL(request.url);
  const session = url.searchParams.get("session");

  if (!session) {
    return redirect(
      `${url.origin}/?link4m_error=missing_session`
    );
  }

  const destination = new URL(
    "/",
    url.origin
  );

  destination.searchParams.set(
    "session",
    session
  );

  return redirect(destination.toString());
}

async function handleLink4mComplete(request, env) {
  const body = await readJson(request);

  const sessionToken =
    normalizeSessionToken(body.sessionToken);

  const sessionHash =
    await sha256(sessionToken);

  const now = Date.now();

  const session = await env.DB.prepare(
    `SELECT *
     FROM link_sessions
     WHERE session_hash = ?`
  )
    .bind(sessionHash)
    .first();

  if (!session) {
    return json(
      {
        ok: false,
        error: "Không tìm thấy phiên Link4m."
      },
      404
    );
  }

  if (now >= Number(session.expires_at)) {
    return json(
      {
        ok: false,
        error: "Phiên Link4m đã hết hạn. Hãy Generate lại."
      },
      403
    );
  }

  if (
    session.completed_at &&
    session.license_key
  ) {
    const existingKey = await env.DB.prepare(
      `SELECT *
       FROM keys
       WHERE license_key = ?`
    )
      .bind(session.license_key)
      .first();

    if (!existingKey) {
      return json(
        {
          ok: false,
          error: "Key của phiên này không còn tồn tại."
        },
        404
      );
    }

    return json({
      ok: true,
      reused: true,
      data: publicKeyRow(
        existingKey,
        now
      )
    });
  }

  const keyRow = await insertUniqueKey(
    env,
    24
  );

  const updateResult = await env.DB.prepare(
    `UPDATE link_sessions
     SET completed_at = ?,
         license_key = ?
     WHERE session_hash = ?
       AND completed_at IS NULL
       AND expires_at > ?`
  )
    .bind(
      now,
      keyRow.license_key,
      sessionHash,
      now
    )
    .run();

  if (!updateResult.meta.changes) {
    await env.DB.prepare(
      `DELETE FROM keys
       WHERE license_key = ?
         AND device_hash IS NULL`
    )
      .bind(keyRow.license_key)
      .run();

    const freshSession =
      await env.DB.prepare(
        `SELECT *
         FROM link_sessions
         WHERE session_hash = ?`
      )
        .bind(sessionHash)
        .first();

    if (
      freshSession &&
      freshSession.license_key
    ) {
      const existingKey =
        await env.DB.prepare(
          `SELECT *
           FROM keys
           WHERE license_key = ?`
        )
          .bind(
            freshSession.license_key
          )
          .first();

      if (existingKey) {
        return json({
          ok: true,
          reused: true,
          data: publicKeyRow(
            existingKey,
            now
          )
        });
      }
    }

    throw new Error(
      "Phiên Link4m đã được sử dụng."
    );
  }

  return json(
    {
      ok: true,
      reused: false,
      data: publicKeyRow(
        keyRow,
        now
      )
    },
    201
  );
}

async function handleClaim(request, env) {
  const body = await readJson(request);

  const key = normalizeKey(body.key);
  const deviceId =
    normalizeDeviceId(body.deviceId);

  const hash =
    await deviceHash(env, deviceId);

  const now = Date.now();

  const row = await env.DB.prepare(
    `SELECT *
     FROM keys
     WHERE license_key = ?`
  )
    .bind(key)
    .first();

  if (!row) {
    return json(
      {
        ok: false,
        valid: false,
        error: "Không tìm thấy key."
      },
      404
    );
  }

  if (row.status === "revoked") {
    return json(
      {
        ok: false,
        valid: false,
        error: "Key đã bị thu hồi."
      },
      403
    );
  }

  if (now >= Number(row.expires_at)) {
    return json(
      {
        ok: false,
        valid: false,
        error: "Key đã hết hạn."
      },
      403
    );
  }

  if (
    row.device_hash &&
    row.device_hash !== hash
  ) {
    return json(
      {
        ok: false,
        valid: false,
        error: "Key đã được kích hoạt trên thiết bị khác."
      },
      409
    );
  }

  if (!row.device_hash) {
    const result = await env.DB.prepare(
      `UPDATE keys
       SET device_hash = ?,
           claimed_at = ?
       WHERE license_key = ?
         AND device_hash IS NULL
         AND status = 'active'
         AND expires_at > ?`
    )
      .bind(
        hash,
        now,
        key,
        now
      )
      .run();

    if (!result.meta.changes) {
      const fresh = await env.DB.prepare(
        `SELECT *
         FROM keys
         WHERE license_key = ?`
      )
        .bind(key)
        .first();

      if (
        !fresh ||
        fresh.device_hash !== hash
      ) {
        return json(
          {
            ok: false,
            valid: false,
            error: "Key vừa được kích hoạt trên thiết bị khác."
          },
          409
        );
      }
    }
  }

  const fresh = await env.DB.prepare(
    `SELECT *
     FROM keys
     WHERE license_key = ?`
  )
    .bind(key)
    .first();

  return json({
    ok: true,
    valid: true,
    data: publicKeyRow(fresh, now)
  });
}

async function handleVerify(request, env) {
  const body = await readJson(request);

  const key = normalizeKey(body.key);
  const deviceId =
    normalizeDeviceId(body.deviceId);

  const hash =
    await deviceHash(env, deviceId);

  const now = Date.now();

  const row = await env.DB.prepare(
    `SELECT *
     FROM keys
     WHERE license_key = ?`
  )
    .bind(key)
    .first();

  if (!row) {
    return json({
      ok: true,
      valid: false,
      reason: "not_found"
    });
  }

  if (row.status === "revoked") {
    return json({
      ok: true,
      valid: false,
      reason: "revoked",
      data: publicKeyRow(row, now)
    });
  }

  if (now >= Number(row.expires_at)) {
    return json({
      ok: true,
      valid: false,
      reason: "expired",
      data: publicKeyRow(row, now)
    });
  }

  if (!row.device_hash) {
    return json({
      ok: true,
      valid: false,
      reason: "not_claimed",
      data: publicKeyRow(row, now)
    });
  }

  if (row.device_hash !== hash) {
    return json({
      ok: true,
      valid: false,
      reason: "wrong_device"
    });
  }

  return json({
    ok: true,
    valid: true,
    data: publicKeyRow(row, now)
  });
}

async function handleRevoke(request, env) {
  if (!isAdmin(request, env)) {
    return json(
      {
        ok: false,
        error: "Không có quyền."
      },
      401
    );
  }

  const body = await readJson(request);
  const key = normalizeKey(body.key);

  const result = await env.DB.prepare(
    `UPDATE keys
     SET status = 'revoked'
     WHERE license_key = ?`
  )
    .bind(key)
    .run();

  return json({
    ok: true,
    changed: result.meta.changes
  });
}

async function route(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (
    request.method === "GET" &&
    path === "/api/health"
  ) {
    return json({
      ok: true,
      service: "Sent Tweaks Get Key",
      database: Boolean(env.DB),
      link4m: Boolean(
        env.LINK4M_API_TOKEN
      )
    });
  }

  if (
    request.method === "POST" &&
    path === "/api/link4m/start"
  ) {
    return handleLink4mStart(
      request,
      env
    );
  }

  if (
    request.method === "POST" &&
    path === "/api/link4m/complete"
  ) {
    return handleLink4mComplete(
      request,
      env
    );
  }

  if (
    request.method === "POST" &&
    path === "/api/demo-key"
  ) {
    return json(
      {
        ok: false,
        error: "Bạn cần vượt Link4m để nhận key."
      },
      403
    );
  }

  if (
    request.method === "POST" &&
    path === "/api/admin/create-key"
  ) {
    return handleAdminCreateKey(
      request,
      env
    );
  }

  if (
    request.method === "POST" &&
    path === "/api/claim"
  ) {
    return handleClaim(request, env);
  }

  if (
    request.method === "POST" &&
    path === "/api/verify"
  ) {
    return handleVerify(request, env);
  }

  if (
    request.method === "POST" &&
    path === "/api/admin/revoke"
  ) {
    return handleRevoke(request, env);
  }

  if (
    request.method === "GET" &&
    (
      path === "/senttwgetkey" ||
      path === "/senttwnhankey"
    )
  ) {
    return handleLink4mLanding(request);
  }

  if (path.startsWith("/api/")) {
    return json(
      {
        ok: false,
        error: "Không tìm thấy API."
      },
      404
    );
  }

  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Lỗi máy chủ.";

      return json(
        {
          ok: false,
          error: message
        },
        400
      );
    }
  }
};
