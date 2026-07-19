const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

async function readJson(request) {
  const type = request.headers.get("content-type") || "";
  if (!type.includes("application/json")) throw new Error("Yêu cầu phải là JSON.");
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
  if (plan !== 12 && plan !== 24) throw new Error("Gói key chỉ hỗ trợ 12 hoặc 24 giờ.");
  return plan;
}

function normalizeKey(value) {
  const key = String(value || "").trim().toUpperCase();
  if (!/^SENT-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(key)) {
    throw new Error("Key không đúng định dạng.");
  }
  return key;
}

function randomPart(length = 5) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => alphabet[b % alphabet.length]).join("");
}

function createKey() {
  return `SENT-${randomPart()}-${randomPart()}-${randomPart()}`;
}

async function sha256(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}

async function deviceHash(env, deviceId) {
  const salt = env.DEVICE_SALT || "senttweaks-default-salt-change-me";
  return sha256(`${salt}:${deviceId}`);
}

function publicKeyRow(row, now = Date.now()) {
  const expired = now >= row.expires_at;
  return {
    key: row.license_key,
    planHours: row.plan_hours,
    bound: Boolean(row.device_hash),
    createdAt: new Date(row.created_at).toISOString(),
    claimedAt: row.claimed_at ? new Date(row.claimed_at).toISOString() : null,
    expiresAt: new Date(row.expires_at).toISOString(),
    remainingSeconds: Math.max(0, Math.floor((row.expires_at - now) / 1000)),
    status: row.status === "revoked" ? "revoked" : expired ? "expired" : "active"
  };
}

async function insertUniqueKey(env, planHours) {
  const now = Date.now();
  const expiresAt = now + planHours * 60 * 60 * 1000;

  for (let attempt = 0; attempt < 5; attempt++) {
    const licenseKey = createKey();
    try {
      await env.DB.prepare(
        `INSERT INTO keys (license_key, plan_hours, created_at, expires_at, status)
         VALUES (?, ?, ?, ?, 'active')`
      ).bind(licenseKey, planHours, now, expiresAt).run();

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
      if (!String(error).toLowerCase().includes("unique")) throw error;
    }
  }
  throw new Error("Không thể tạo key mới. Hãy thử lại.");
}

function isAdmin(request, env) {
  const expected = env.ADMIN_TOKEN;
  if (!expected) return false;
  return request.headers.get("authorization") === `Bearer ${expected}`;
}

async function handleCreateKey(request, env, demoOnly = false) {
  if (demoOnly) {
    if (String(env.DEMO_MODE).toLowerCase() !== "true") {
      return json({ ok: false, error: "Chế độ nhận key thử nghiệm đã tắt. Cần cấu hình callback Link4M." }, 403);
    }
  } else if (!isAdmin(request, env)) {
    return json({ ok: false, error: "Không có quyền tạo key." }, 401);
  }

  const body = await readJson(request);
  const planHours = normalizePlan(body.planHours);
  const row = await insertUniqueKey(env, planHours);
  return json({ ok: true, data: publicKeyRow(row) }, 201);
}

async function handleClaim(request, env) {
  const body = await readJson(request);
  const key = normalizeKey(body.key);
  const deviceId = normalizeDeviceId(body.deviceId);
  const hash = await deviceHash(env, deviceId);
  const now = Date.now();

  const row = await env.DB.prepare("SELECT * FROM keys WHERE license_key = ?").bind(key).first();
  if (!row) return json({ ok: false, valid: false, error: "Không tìm thấy key." }, 404);
  if (row.status === "revoked") return json({ ok: false, valid: false, error: "Key đã bị thu hồi." }, 403);
  if (now >= row.expires_at) return json({ ok: false, valid: false, error: "Key đã hết hạn." }, 403);

  if (row.device_hash && row.device_hash !== hash) {
    return json({ ok: false, valid: false, error: "Key đã được kích hoạt trên thiết bị khác." }, 409);
  }

  if (!row.device_hash) {
    const result = await env.DB.prepare(
      `UPDATE keys SET device_hash = ?, claimed_at = ?
       WHERE license_key = ? AND device_hash IS NULL AND status = 'active' AND expires_at > ?`
    ).bind(hash, now, key, now).run();

    if (!result.meta.changes) {
      const fresh = await env.DB.prepare("SELECT * FROM keys WHERE license_key = ?").bind(key).first();
      if (!fresh || fresh.device_hash !== hash) {
        return json({ ok: false, valid: false, error: "Key vừa được kích hoạt trên thiết bị khác." }, 409);
      }
    }
  }

  const fresh = await env.DB.prepare("SELECT * FROM keys WHERE license_key = ?").bind(key).first();
  return json({ ok: true, valid: true, data: publicKeyRow(fresh, now) });
}

async function handleVerify(request, env) {
  const body = await readJson(request);
  const key = normalizeKey(body.key);
  const deviceId = normalizeDeviceId(body.deviceId);
  const hash = await deviceHash(env, deviceId);
  const now = Date.now();

  const row = await env.DB.prepare("SELECT * FROM keys WHERE license_key = ?").bind(key).first();
  if (!row) return json({ ok: true, valid: false, reason: "not_found" });
  if (row.status === "revoked") return json({ ok: true, valid: false, reason: "revoked", data: publicKeyRow(row, now) });
  if (now >= row.expires_at) return json({ ok: true, valid: false, reason: "expired", data: publicKeyRow(row, now) });
  if (!row.device_hash) return json({ ok: true, valid: false, reason: "not_claimed", data: publicKeyRow(row, now) });
  if (row.device_hash !== hash) return json({ ok: true, valid: false, reason: "wrong_device" });

  return json({ ok: true, valid: true, data: publicKeyRow(row, now) });
}

async function handleRevoke(request, env) {
  if (!isAdmin(request, env)) return json({ ok: false, error: "Không có quyền." }, 401);
  const body = await readJson(request);
  const key = normalizeKey(body.key);
  const result = await env.DB.prepare("UPDATE keys SET status = 'revoked' WHERE license_key = ?").bind(key).run();
  return json({ ok: true, changed: result.meta.changes });
}

async function route(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "GET" && path === "/api/health") {
    return json({ ok: true, service: "Sent Tweaks Get Key", database: Boolean(env.DB) });
  }

  if (request.method === "POST" && path === "/api/demo-key") return handleCreateKey(request, env, true);
  if (request.method === "POST" && path === "/api/admin/create-key") return handleCreateKey(request, env, false);
  if (request.method === "POST" && path === "/api/claim") return handleClaim(request, env);
  if (request.method === "POST" && path === "/api/verify") return handleVerify(request, env);
  if (request.method === "POST" && path === "/api/admin/revoke") return handleRevoke(request, env);

  // Tên callback đã yêu cầu. Hiện trả về trang chủ; tích hợp xác minh Link4M sau khi có API/callback thật.
  if (request.method === "GET" && (path === "/senttwgetkey" || path === "/senttwnhankey")) {
    return Response.redirect(`${url.origin}/?callback=${path.slice(1)}`, 302);
  }

  if (path.startsWith("/api/")) return json({ ok: false, error: "Không tìm thấy API." }, 404);
  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Lỗi máy chủ.";
      return json({ ok: false, error: message }, 400);
    }
  }
};
