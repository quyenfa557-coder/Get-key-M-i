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
  const type =
    request.headers.get("content-type") || "";

  if (!type.includes("application/json")) {
    throw new Error("Yêu cầu phải là JSON.");
  }

  return request.json();
}

function normalizeDeviceId(value) {
  const id = String(value || "").trim();

  if (id.length < 6 || id.length > 200) {
    throw new Error(
      "Device ID phải có từ 6 đến 200 ký tự."
    );
  }

  return id;
}

function normalizePlan(value) {
  const plan = Number(value || 24);

  if (plan !== 24) {
    throw new Error(
      "Hệ thống chỉ hỗ trợ key 24 giờ."
    );
  }

  return 24;
}


function normalizeKeyFormat(value) {
  return String(value || "")
    .trim()
    .toUpperCase() === "SUNNY"
      ? "SUNNY"
      : "SENT";
}

function normalizeKey(value) {
  let key = String(value ?? "")
    .trim()
    .toUpperCase()
    .replace(/\u0000/g, "")
    .replace(/[‐‑‒–—−]/g, "-")
    .replace(/\s+/g, "");

  /*
   * Libloader có thể tự thêm SUNNY- vào key đã có SUNNY-:
   * SUNNY-SUNNY-7K9P-H38Q-Z52N
   * → SUNNY-7K9P-H38Q-Z52N
   */
  while (key.startsWith("SUNNY-SUNNY-")) {
    key = key.slice("SUNNY-".length);
  }

  /*
   * Libloader bọc key SENT:
   * SUNNY-SENT-ABCDE-FGHIJ-KLMNO
   * → SENT-ABCDE-FGHIJ-KLMNO
   */
  if (key.startsWith("SUNNY-SENT-")) {
    key = key.slice("SUNNY-".length);
  }

  /*
   * Cho phép phần thân không có tiền tố.
   */
  if (/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key)) {
    key = `SUNNY-${key}`;
  } else if (
    /^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(key)
  ) {
    key = `SENT-${key}`;
  }

  const validSunny =
    /^SUNNY-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key);

  const validSent =
    /^SENT-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(key);

  if (!validSunny && !validSent) {
    throw new Error(
      "Key không đúng định dạng. Dùng SUNNY-XXXX-XXXX-XXXX hoặc SENT-XXXXX-XXXXX-XXXXX."
    );
  }

  return key;
}

function normalizeSessionToken(value) {
  const token = String(value || "").trim();

  if (!/^[A-Za-z0-9_-]{40,100}$/.test(token)) {
    throw new Error(
      "Mã phiên Link4m không hợp lệ."
    );
  }

  return token;
}

function randomPart(length = 5) {
  const alphabet =
    "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  const bytes = new Uint8Array(length);

  crypto.getRandomValues(bytes);

  return Array.from(
    bytes,
    byte => alphabet[byte % alphabet.length]
  ).join("");
}

function createKey(keyFormat = "SENT") {
  const format =
    normalizeKeyFormat(keyFormat);

  if (format === "SUNNY") {
    return `SUNNY-${randomPart(4)}-${randomPart(4)}-${randomPart(4)}`;
  }

  return `SENT-${randomPart(5)}-${randomPart(5)}-${randomPart(5)}`;
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
  const bytes =
    new TextEncoder().encode(text);

  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      bytes
    );

  return Array.from(
    new Uint8Array(digest),
    byte =>
      byte.toString(16).padStart(2, "0")
  ).join("");
}

/*
 * MD5 is required only by the old libloader.so wire protocol. Cloudflare's
 * Web Crypto implementation does not expose MD5, so keep this small,
 * self-contained implementation next to the compatibility adapter.
 */
function md5Hex(input) {
  const source = new TextEncoder().encode(String(input));
  const paddedLength = Math.ceil((source.length + 9) / 64) * 64;
  const data = new Uint8Array(paddedLength);
  data.set(source);
  data[source.length] = 0x80;

  const view = new DataView(data.buffer);
  const bitLength = source.length * 8;
  view.setUint32(paddedLength - 8, bitLength >>> 0, true);
  view.setUint32(
    paddedLength - 4,
    Math.floor(bitLength / 0x100000000) >>> 0,
    true
  );

  const shifts = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ];
  const constants = Array.from(
    { length: 64 },
    (_, index) =>
      Math.floor(Math.abs(Math.sin(index + 1)) * 0x100000000) >>> 0
  );
  const rotateLeft = (value, count) =>
    ((value << count) | (value >>> (32 - count))) >>> 0;

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  for (let offset = 0; offset < data.length; offset += 64) {
    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;

    for (let index = 0; index < 64; index += 1) {
      let mixed;
      let wordIndex;

      if (index < 16) {
        mixed = (b & c) | (~b & d);
        wordIndex = index;
      } else if (index < 32) {
        mixed = (d & b) | (~d & c);
        wordIndex = (5 * index + 1) % 16;
      } else if (index < 48) {
        mixed = b ^ c ^ d;
        wordIndex = (3 * index + 5) % 16;
      } else {
        mixed = c ^ (b | ~d);
        wordIndex = (7 * index) % 16;
      }

      const sum = (
        a +
        (mixed >>> 0) +
        constants[index] +
        view.getUint32(offset + wordIndex * 4, true)
      ) >>> 0;
      const previousD = d;
      d = c;
      c = b;
      b = (b + rotateLeft(sum, shifts[index])) >>> 0;
      a = previousD;
    }

    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }

  return [a0, b0, c0, d0]
    .flatMap(word => [
      word & 0xff,
      (word >>> 8) & 0xff,
      (word >>> 16) & 0xff,
      (word >>> 24) & 0xff
    ])
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}



/*
 * =====================================================
 * SENT AUTH V3 — SIGNED LICENSE RESPONSES
 * =====================================================
 * AUTH_PRIVATE_KEY_PEM must be a Cloudflare Secret containing
 * an RSA PKCS#8 private key. The matching public key is embedded
 * in Login.h. Never commit the private key to GitHub.
 */
const AUTH_RESPONSE_PROTOCOL = 4;
const AUTH_RESPONSE_KEY_ID = "sent-auth-rsa-2026-08-v4";
const AUTH_DEFAULT_BUILD_ID = "sent-menu-2026.08.07-r1";
const AUTH_DEFAULT_CLIENT_VERSION = "5.2.1";
const AUTH_MAX_CLOCK_SKEW_MS = 10 * 60 * 1000;

function authServerEnabled(env) {
  const value = String(env.AUTH_ENABLED ?? "true").trim().toLowerCase();
  return !["0", "false", "off", "disabled"].includes(value);
}

function authActiveBuildId(env) {
  return String(env.AUTH_ACTIVE_BUILD_ID || AUTH_DEFAULT_BUILD_ID).trim();
}

function authExpectedClientVersion(env) {
  return String(env.AUTH_CLIENT_VERSION || AUTH_DEFAULT_CLIENT_VERSION).trim();
}

function authPolicyGeneration(env) {
  const value = Number(env.AUTH_POLICY_GENERATION ?? 1);
  return Number.isSafeInteger(value) && value > 0 ? value : 1;
}

let authPrivateKeyCache = null;
let authPrivateKeySource = "";

function authBase64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function authPemToBytes(pemText) {
  const normalized = String(pemText || "")
    .replace(/\\n/g, "\n")
    .trim();

  const base64 = normalized
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");

  if (!base64) {
    throw new Error("AUTH_PRIVATE_KEY_PEM không hợp lệ.");
  }

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function authGetPrivateKey(env) {
  const pem = String(env.AUTH_PRIVATE_KEY_PEM || "").trim();
  if (!pem) {
    throw new Error("Máy chủ chưa cấu hình AUTH_PRIVATE_KEY_PEM.");
  }

  if (authPrivateKeyCache && authPrivateKeySource === pem) {
    return authPrivateKeyCache;
  }

  const keyBytes = authPemToBytes(pem);
  authPrivateKeyCache = await crypto.subtle.importKey(
    "pkcs8",
    keyBytes,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );
  authPrivateKeySource = pem;
  return authPrivateKeyCache;
}

function normalizeAuthNonce(value) {
  const nonce = String(value || "").trim().toLowerCase();
  if (!/^[a-f0-9]{48}$/.test(nonce)) {
    throw new Error("Nonce xác thực không hợp lệ.");
  }
  return nonce;
}

function normalizeAuthClientTime(value) {
  const clientTimeMs = Number(value);
  if (!Number.isSafeInteger(clientTimeMs) || clientTimeMs <= 0) {
    throw new Error("Thời gian client không hợp lệ.");
  }

  if (Math.abs(Date.now() - clientTimeMs) > AUTH_MAX_CLOCK_SKEW_MS) {
    throw new Error("Đồng hồ thiết bị lệch quá nhiều.");
  }
  return clientTimeMs;
}

function normalizeAuthProtocol(value) {
  const protocolVersion = Number(value);
  if (protocolVersion !== AUTH_RESPONSE_PROTOCOL) {
    throw new Error("Phiên bản xác thực không được hỗ trợ.");
  }
  return protocolVersion;
}

function normalizeAuthBuildId(value) {
  const buildId = String(value || "").trim();
  if (!/^[A-Za-z0-9._:-]{8,96}$/.test(buildId)) {
    throw new Error("Build ID không hợp lệ.");
  }
  return buildId;
}

function normalizeAuthClientVersion(value) {
  const version = String(value || "").trim();
  if (!/^[A-Za-z0-9._+-]{1,40}$/.test(version)) {
    throw new Error("Client version không hợp lệ.");
  }
  return version;
}

function readAuthRequestMetadata(body) {
  return {
    nonce: normalizeAuthNonce(body.nonce),
    clientTimeMs: normalizeAuthClientTime(body.clientTimeMs),
    protocolVersion: normalizeAuthProtocol(body.protocolVersion),
    buildId: normalizeAuthBuildId(body.buildId),
    clientVersion: normalizeAuthClientVersion(body.clientVersion)
  };
}

function enforceAuthPolicy(env, metadata) {
  if (!authServerEnabled(env)) {
    throw new Error("AUTH_DISABLED");
  }
  if (metadata.buildId !== authActiveBuildId(env)) {
    throw new Error("BUILD_REVOKED_OR_OUTDATED");
  }
  if (metadata.clientVersion !== authExpectedClientVersion(env)) {
    throw new Error("CLIENT_VERSION_REVOKED_OR_OUTDATED");
  }
}

function authCanonicalPayload({
  endpoint,
  nonce,
  key,
  deviceDigest,
  valid,
  status,
  bound,
  planHours,
  expiresAtMs,
  serverTimeMs,
  buildId,
  clientVersion,
  policyGeneration,
  sessionId
}) {
  return [
    "SENT-AUTH-V4",
    `endpoint=${endpoint}`,
    `nonce=${nonce}`,
    `key=${key}`,
    `deviceDigest=${deviceDigest}`,
    `valid=${valid ? 1 : 0}`,
    `status=${status}`,
    `bound=${bound ? 1 : 0}`,
    `planHours=${planHours}`,
    `expiresAtMs=${expiresAtMs}`,
    `serverTimeMs=${serverTimeMs}`,
    `buildId=${buildId}`,
    `clientVersion=${clientVersion}`,
    `policyGeneration=${policyGeneration}`,
    `sessionId=${sessionId}`
  ].join("\n");
}

async function authSignPayload(env, canonicalPayload) {
  const privateKey = await authGetPrivateKey(env);
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(canonicalPayload)
  );
  return authBase64UrlEncode(new Uint8Array(signature));
}

async function withSignedAuthResponse(
  env,
  endpoint,
  requestMetadata,
  deviceId,
  payload
) {
  if (
    !payload ||
    payload.ok !== true ||
    payload.valid !== true ||
    !payload.data
  ) {
    return payload;
  }

  enforceAuthPolicy(env, requestMetadata);

  const serverTimeMs = Date.now();
  const deviceDigest = await sha256(deviceId);
  const expiresAtMs = Number(
    payload.data.expiresAtMs ?? Date.parse(payload.data.expiresAt)
  );

  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= serverTimeMs) {
    throw new Error("Dữ liệu thời hạn license không hợp lệ.");
  }

  const buildId = authActiveBuildId(env);
  const clientVersion = authExpectedClientVersion(env);
  const policyGeneration = authPolicyGeneration(env);
  const sessionId = randomToken(24);

  const data = {
    ...payload.data,
    expiresAtMs
  };

  const canonical = authCanonicalPayload({
    endpoint,
    nonce: requestMetadata.nonce,
    key: String(data.key || ""),
    deviceDigest,
    valid: true,
    status: String(data.status || ""),
    bound: Boolean(data.bound),
    planHours: Number(data.planHours || 0),
    expiresAtMs,
    serverTimeMs,
    buildId,
    clientVersion,
    policyGeneration,
    sessionId
  });

  const signature = await authSignPayload(env, canonical);

  return {
    ...payload,
    data,
    auth: {
      protocolVersion: AUTH_RESPONSE_PROTOCOL,
      keyId: AUTH_RESPONSE_KEY_ID,
      endpoint,
      nonce: requestMetadata.nonce,
      deviceDigest,
      serverTimeMs,
      buildId,
      clientVersion,
      policyGeneration,
      sessionId,
      signature
    }
  };
}

async function deviceHash(env, deviceId) {
  const salt =
    env.DEVICE_SALT ||
    "senttweaks-default-salt-change-me";

  return sha256(`${salt}:${deviceId}`);
}

const MULTI_DEVICE_PREFIX = "SENTMULTI:v1:";

function normalizeMaxDevices(value) {
  const maxDevices = Number(value ?? 1);

  if (!Number.isInteger(maxDevices) || maxDevices < 0 || maxDevices > 100) {
    throw new Error("Giới hạn thiết bị phải từ 0 đến 100. Dùng 0 để không giới hạn.");
  }

  return maxDevices;
}

function parseDeviceBinding(value) {
  const raw = String(value || "").trim();

  if (!raw) {
    return {
      multi: false,
      limit: 1,
      hashes: []
    };
  }

  if (!raw.startsWith(MULTI_DEVICE_PREFIX)) {
    return {
      multi: false,
      limit: 1,
      hashes: [raw]
    };
  }

  const payload = raw.slice(MULTI_DEVICE_PREFIX.length);
  const separator = payload.indexOf(":");

  if (separator < 0) {
    return {
      multi: false,
      limit: 1,
      hashes: [raw]
    };
  }

  const limit = Number(payload.slice(0, separator));
  const hashes = payload
    .slice(separator + 1)
    .split(",")
    .map(item => item.trim())
    .filter(Boolean);

  if (!Number.isInteger(limit) || limit < 0 || limit > 100) {
    return {
      multi: false,
      limit: 1,
      hashes: [raw]
    };
  }

  return {
    multi: true,
    limit,
    hashes: [...new Set(hashes)]
  };
}

function serializeDeviceBinding(limit, hashes) {
  return `${MULTI_DEVICE_PREFIX}${limit}:${[...new Set(hashes)].join(",")}`;
}

function deviceBindingInfo(row) {
  const binding = parseDeviceBinding(row?.device_hash);

  return {
    maxDevices: binding.limit,
    devicesUsed: binding.hashes.length,
    bound: binding.hashes.length > 0,
    hashes: binding.hashes,
    multi: binding.multi
  };
}

async function claimDeviceForKey(env, key, row, hash, now) {
  let currentRow = row;

  for (let attempt = 0; attempt < 4; attempt += 1) {
    const binding = parseDeviceBinding(currentRow.device_hash);

    if (binding.hashes.includes(hash)) {
      return {
        ok: true,
        row: currentRow
      };
    }

    if (binding.limit !== 0 && binding.hashes.length >= binding.limit) {
      return {
        ok: false,
        error: "Key đã đạt giới hạn thiết bị."
      };
    }

    const nextHashes = [...binding.hashes, hash];
    const nextValue =
      !binding.multi && !currentRow.device_hash && binding.limit === 1
        ? hash
        : serializeDeviceBinding(binding.limit, nextHashes);

    const previousValue = currentRow.device_hash ?? null;

    const result = await env.DB.prepare(
      `UPDATE keys
       SET device_hash = ?,
           claimed_at = COALESCE(claimed_at, ?)
       WHERE license_key = ?
         AND status = 'active'
         AND expires_at > ?
         AND (
           (device_hash IS NULL AND ? IS NULL)
           OR device_hash = ?
         )`
    )
      .bind(
        nextValue,
        now,
        key,
        now,
        previousValue,
        previousValue
      )
      .run();

    if (result.meta.changes) {
      currentRow = await env.DB.prepare(
        `SELECT * FROM keys WHERE license_key = ? LIMIT 1`
      )
        .bind(key)
        .first();

      return {
        ok: true,
        row: currentRow
      };
    }

    currentRow = await env.DB.prepare(
      `SELECT * FROM keys WHERE license_key = ? LIMIT 1`
    )
      .bind(key)
      .first();

    if (!currentRow) {
      return {
        ok: false,
        error: "Không tìm thấy key."
      };
    }
  }

  return {
    ok: false,
    error: "Không thể liên kết thiết bị lúc này. Hãy thử lại."
  };
}

function publicKeyRow(row, now = Date.now()) {
  const createdAt =
    Number(row.created_at);

  const claimedAt =
    row.claimed_at
      ? Number(row.claimed_at)
      : null;

  const expiresAt =
    Number(row.expires_at);

  const expired =
    now >= expiresAt;

  const binding =
    deviceBindingInfo(row);

  return {
    key: row.license_key,
    planHours: Number(row.plan_hours),
    bound: binding.bound,
    maxDevices: binding.maxDevices,
    devicesUsed: binding.devicesUsed,

    createdAt:
      new Date(createdAt).toISOString(),

    claimedAt:
      claimedAt
        ? new Date(claimedAt).toISOString()
        : null,

    expiresAt:
      new Date(expiresAt).toISOString(),

    expiresAtMs: expiresAt,

    remainingSeconds:
      Math.max(
        0,
        Math.floor(
          (expiresAt - now) / 1000
        )
      ),

    status:
      row.status === "revoked"
        ? "revoked"
        : expired
          ? "expired"
          : "active"
  };
}

async function insertUniqueKey(
  env,
  planHours,
  keyFormat = "SENT",
  maxDevices = 1
) {
  const now = Date.now();

  const expiresAt =
    now +
    planHours * 60 * 60 * 1000;

  const deviceLimit =
    normalizeMaxDevices(maxDevices);

  const initialBinding =
    deviceLimit === 1
      ? null
      : serializeDeviceBinding(deviceLimit, []);

  for (
    let attempt = 0;
    attempt < 5;
    attempt++
  ) {
    const licenseKey =
      createKey(keyFormat);

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
      const message =
        String(error).toLowerCase();

      if (!message.includes("unique")) {
        throw error;
      }
    }
  }

  throw new Error(
    "Không thể tạo key mới. Hãy thử lại."
  );
}

function isAdmin(request, env) {
  const expected =
    String(env.ADMIN_TOKEN || "");

  return (
    Boolean(expected) &&
    request.headers.get("authorization") ===
      `Bearer ${expected}`
  );
}

async function handleAdminCreateKey(
  request,
  env
) {
  if (!isAdmin(request, env)) {
    return json(
      {
        ok: false,
        error: "Không có quyền tạo key."
      },
      401
    );
  }

  const body =
    await readJson(request);

  const planHours =
    normalizePlan(body.planHours);

  const maxDevices =
    normalizeMaxDevices(
      body.maxDevices
    );

  const row =
    await insertUniqueKey(
      env,
      planHours,
      "SENT",
      maxDevices
    );

  return json(
    {
      ok: true,
      data: publicKeyRow(row)
    },
    201
  );
}

async function handleAdminLink4mStats(
  request,
  env
) {
  if (!isAdmin(request, env)) {
    return json(
      {
        ok: false,
        error: "Không có quyền xem thống kê."
      },
      401
    );
  }

  const now = Date.now();
  const vietnamOffset = 7 * 60 * 60 * 1000;
  const dayMs = 24 * 60 * 60 * 1000;
  const todayStart =
    Math.floor((now + vietnamOffset) / dayMs) * dayMs - vietnamOffset;

  const summary = await env.DB.prepare(
    `SELECT
       COUNT(DISTINCT ls.license_key) AS total,
       COUNT(DISTINCT CASE
         WHEN ls.completed_at >= ? THEN ls.license_key
       END) AS today,
       COUNT(DISTINCT CASE
         WHEN k.status = 'active' AND k.expires_at > ? THEN ls.license_key
       END) AS active,
       COUNT(DISTINCT CASE
         WHEN k.status != 'revoked' AND k.expires_at <= ? THEN ls.license_key
       END) AS expired,
       COUNT(DISTINCT CASE
         WHEN k.status = 'revoked' THEN ls.license_key
       END) AS revoked
     FROM link_sessions AS ls
     LEFT JOIN keys AS k
       ON k.license_key = ls.license_key
     WHERE ls.completed_at IS NOT NULL
       AND ls.license_key IS NOT NULL`
  )
    .bind(todayStart, now, now)
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

  const recent = (recentResult.results || []).map(row => {
    const data = publicKeyRow(row, now);

    return {
      ...data,
      createdAt: new Date(Number(row.completed_at || row.created_at)).toISOString()
    };
  });

  return json({
    ok: true,
    generatedAt: new Date(now).toISOString(),
    stats: {
      total: Number(summary?.total || 0),
      today: Number(summary?.today || 0),
      active: Number(summary?.active || 0),
      expired: Number(summary?.expired || 0),
      revoked: Number(summary?.revoked || 0)
    },
    recent
  });
}

async function link4mShortenUrl(apiToken, destinationUrl) {
  const link4mApi = new URL(
    "https://link4m.co/api-shorten/v2"
  );

  link4mApi.searchParams.set(
    "api",
    apiToken
  );

  link4mApi.searchParams.set(
    "url",
    destinationUrl
  );

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

  return shortUrl;
}

async function link4mStep2Proof(
  sessionToken,
  apiToken
) {
  // Proof is never returned by /api/link4m/start. It is created only after
  // the first Link4m callback reaches the Worker, so /api/link4m/complete
  // cannot be called successfully after only one shortened link.
  return sha256(
    `sent-link4m-v2:${sessionToken}:${apiToken}`
  );
}

function normalizeLink4mProof(value) {
  const proof = String(value || "").trim().toLowerCase();

  if (!/^[a-f0-9]{64}$/.test(proof)) {
    throw new Error(
      "Xác nhận bước Link4m thứ hai không hợp lệ."
    );
  }

  return proof;
}

async function handleLink4mStart(
  request,
  env
) {
  const apiToken =
    String(
      env.LINK4M_API_TOKEN || ""
    ).trim();

  if (!apiToken) {
    return json(
      {
        ok: false,
        error:
          "Máy chủ chưa cấu hình LINK4M_API_TOKEN."
      },
      503
    );
  }

  const now = Date.now();

  const expiresAt =
    now + 20 * 60 * 1000;

  const sessionToken =
    randomToken(32);

  const sessionHash =
    await sha256(sessionToken);

  await env.DB.prepare(
    `DELETE FROM link_sessions
     WHERE expires_at < ?`
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

  callbackUrl.searchParams.set(
    "step",
    "1"
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
      result = JSON.parse(raw);
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
       WHERE session_hash = ?`
    )
      .bind(sessionHash)
      .run();

    throw error;
  }
}

async function handleLink4mLanding(
  request,
  env
) {
  const url = new URL(request.url);
  const path = url.pathname;

  let sessionToken;

  try {
    sessionToken = normalizeSessionToken(
      url.searchParams.get("session")
    );
  } catch {
    return redirect(
      `${url.origin}/?link4m_error=missing_session`
    );
  }

  const sessionHash = await sha256(
    sessionToken
  );

  const now = Date.now();
  const session = await env.DB.prepare(
    `SELECT *
     FROM link_sessions
     WHERE session_hash = ?`
  )
    .bind(sessionHash)
    .first();

  if (!session) {
    return redirect(
      `${url.origin}/?link4m_error=session_not_found`
    );
  }

  if (now >= Number(session.expires_at)) {
    return redirect(
      `${url.origin}/?link4m_error=session_expired`
    );
  }

  const apiToken = String(
    env.LINK4M_API_TOKEN || ""
  ).trim();

  if (!apiToken) {
    return redirect(
      `${url.origin}/?link4m_error=link4m_not_configured`
    );
  }

  // STEP 1 completed -> create and send the user through Link4m a second time.
  if (path === "/senttwgetkey") {
    try {
      const proof = await link4mStep2Proof(
        sessionToken,
        apiToken
      );

      const callback2 = new URL(
        "/senttwnhankey",
        url.origin
      );

      callback2.searchParams.set(
        "session",
        sessionToken
      );

      callback2.searchParams.set(
        "proof",
        proof
      );

      const shortUrl2 = await link4mShortenUrl(
        apiToken,
        callback2.toString()
      );

      return redirect(shortUrl2);
    } catch {
      return redirect(
        `${url.origin}/?link4m_error=step2_create_failed`
      );
    }
  }

  // STEP 2 completed -> verify server-generated proof, then allow the public
  // page to call /api/link4m/complete. app.js remains unchanged: it forwards
  // the whole composite value as sessionToken.
  if (path === "/senttwnhankey") {
    let proof;

    try {
      proof = normalizeLink4mProof(
        url.searchParams.get("proof")
      );
    } catch {
      return redirect(
        `${url.origin}/?link4m_error=step2_proof_missing`
      );
    }

    const expectedProof = await link4mStep2Proof(
      sessionToken,
      apiToken
    );

    if (proof !== expectedProof) {
      return redirect(
        `${url.origin}/?link4m_error=step2_proof_invalid`
      );
    }

    const destination = new URL(
      "/",
      url.origin
    );

    // Dot is intentionally used only in this composite browser value.
    // The raw session token itself still passes normalizeSessionToken().
    destination.searchParams.set(
      "session",
      `${sessionToken}.${proof}`
    );

    return redirect(
      destination.toString()
    );
  }

  return redirect(
    `${url.origin}/?link4m_error=invalid_step`
  );
}

async function handleLink4mComplete(
  request,
  env
) {
  const body =
    await readJson(request);

  const compositeToken = String(
    body.sessionToken || ""
  ).trim();

  const separatorIndex =
    compositeToken.lastIndexOf(".");

  if (separatorIndex <= 0) {
    return json(
      {
        ok: false,
        error:
          "Bạn phải hoàn thành đủ 2 bước Link4m."
      },
      403
    );
  }

  const sessionToken =
    normalizeSessionToken(
      compositeToken.slice(
        0,
        separatorIndex
      )
    );

  const proof =
    normalizeLink4mProof(
      compositeToken.slice(
        separatorIndex + 1
      )
    );

  const apiToken = String(
    env.LINK4M_API_TOKEN || ""
  ).trim();

  if (!apiToken) {
    return json(
      {
        ok: false,
        error:
          "Máy chủ chưa cấu hình LINK4M_API_TOKEN."
      },
      503
    );
  }

  const expectedProof =
    await link4mStep2Proof(
      sessionToken,
      apiToken
    );

  if (proof !== expectedProof) {
    return json(
      {
        ok: false,
        error:
          "Bước Link4m thứ hai chưa được xác nhận."
      },
      403
    );
  }

  const sessionHash =
    await sha256(sessionToken);

  const now = Date.now();

  const session =
    await env.DB.prepare(
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
        error:
          "Không tìm thấy phiên Link4m."
      },
      404
    );
  }

  if (
    now >= Number(session.expires_at)
  ) {
    return json(
      {
        ok: false,
        error:
          "Phiên Link4m đã hết hạn. Hãy Generate lại."
      },
      403
    );
  }

  if (
    session.completed_at &&
    session.license_key
  ) {
    const existingKey =
      await env.DB.prepare(
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
          error:
            "Key của phiên này không còn tồn tại."
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

  const keyRow =
    await insertUniqueKey(
      env,
      24
    );

  const updateResult =
    await env.DB.prepare(
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

/*
 * =====================================================
 * SENT AUTH — TƯƠNG THÍCH LIBLOADER CŨ VÀ LOGIN.H MỚI
 * =====================================================
 */

const LEGACY_PRODUCT_ID =
  "sent-tweaks";

const LEGACY_SIG_ALG =
  "SHA256withECDSA";

function authIsObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function authFindString(
  value,
  acceptedNames
) {
  if (Array.isArray(value)) {
    for (const item of value) {
      const result =
        authFindString(
          item,
          acceptedNames
        );

      if (result) {
        return result;
      }
    }

    return "";
  }

  if (!authIsObject(value)) {
    return "";
  }

  for (
    const [name, candidate]
    of Object.entries(value)
  ) {
    if (
      acceptedNames.has(
        name.toLowerCase()
      ) &&
      typeof candidate === "string" &&
      candidate.trim()
    ) {
      return candidate.trim();
    }
  }

  for (
    const candidate
    of Object.values(value)
  ) {
    const result =
      authFindString(
        candidate,
        acceptedNames
      );

    if (result) {
      return result;
    }
  }

  return "";
}

function authRandomHex(
  byteLength = 32
) {
  const bytes =
    new Uint8Array(byteLength);

  crypto.getRandomValues(bytes);

  return Array.from(
    bytes,
    byte =>
      byte.toString(16).padStart(2, "0")
  ).join("");
}

function authPositiveInteger(
  value,
  fallback = 0
) {
  const number =
    Number(value);

  if (
    Number.isSafeInteger(number) &&
    number > 0
  ) {
    return number;
  }

  return fallback;
}


function authIsLegacyClient(request) {
  const userAgent =
    request.headers.get(
      "user-agent"
    ) || "";


  return (
    request.headers.has("x-nonce") ||
    request.headers.has("x-sig") ||
    request.headers.has("x-build-id") ||
    userAgent.includes("SunnyMod/1.0")
  );
}

function authNormalizeBody(
  originalBody
) {
  const key =
    authFindString(
      originalBody,
      new Set([
        "key",
        "licensekey",
        "license_key",
        "userkey",
        "user_key",
        "code"
      ])
    );

  const deviceId =
    authFindString(
      originalBody,
      new Set([
        "deviceid",
        "device_id",
        "stabledeviceid",
        "stable_device_id",
        "androidid",
        "android_id",
        "device"
      ])
    );

  const nonce =
    authFindString(
      originalBody,
      new Set([
        "nonce",
        "requestnonce",
        "request_nonce"
      ])
    );

  const clientTimeMs = Number(
    originalBody?.clientTimeMs ??
    originalBody?.client_time_ms ??
    0
  );

  const protocolVersion = Number(
    originalBody?.protocolVersion ??
    originalBody?.protocol_version ??
    0
  );

  const buildId = authFindString(
    originalBody,
    new Set(["buildid", "build_id"])
  );

  const clientVersion = authFindString(
    originalBody,
    new Set(["clientversion", "client_version", "version"])
  );

  return {
    key,
    deviceId,
    nonce,
    clientTimeMs,
    protocolVersion,
    buildId,
    clientVersion
  };
}

async function authReadResponse(
  response
) {
  const text =
    await response.text();

  try {
    return {
      payload: JSON.parse(text),
      rawText: text
    };
  } catch {
    return {
      payload: null,
      rawText: text
    };
  }
}

function authBuildLegacySuccess() {
  return {
    ok: false,
    valid: false,
    error: "CLIENT_UPGRADE_REQUIRED"
  };
}



/*
 * =====================================================
 * SENT TWEAKS NATIVE AUTH
 * =====================================================
 * Native lib POSTs application/x-www-form-urlencoded:
 *   key=...&deviceid=...&tokenanti=...
 * /api/claim is the only native authentication endpoint.
 */
const NATIVE_TOKEN_CODES = Object.freeze({
  "A": 876543,
  "B": 124367,
  "C": 456789,
  "D": 372910,
  "E": 583210,
  "F": 290381,
  "G": 104783,
  "H": 389104,
  "I": 759283,
  "J": 467182,
  "K": 905173,
  "L": 614273,
  "M": 835612,
  "N": 248359,
  "O": 631759,
  "P": 493102,
  "Q": 721098,
  "R": 384560,
  "S": 560173,
  "T": 193847,
  "U": 782356,
  "V": 149273,
  "W": 367205,
  "X": 982147,
  "Y": 518374,
  "Z": 673892,
  "a": 715493,
  "b": 204895,
  "c": 347210,
  "d": 598102,
  "e": 861320,
  "f": 190478,
  "g": 523618,
  "h": 704329,
  "i": 315279,
  "j": 239815,
  "k": 408573,
  "l": 629174,
  "m": 847320,
  "n": 150283,
  "o": 479630,
  "p": 526384,
  "q": 371029,
  "r": 860175,
  "s": 204987,
  "t": 914502,
  "u": 637491,
  "v": 320485,
  "w": 190384,
  "x": 582713,
  "y": 945210,
  "z": 750361,
  "0": 428391,
  "1": 610283,
  "2": 357492,
  "3": 801473,
  "4": 295071,
  "5": 748291,
  "6": 182493,
  "7": 903275,
  "8": 549183,
  "9": 671294,
  "!": 493012,
  "@": 576103,
  "#": 293745,
  "$": 194837,
  "%": 608412,
  "^": 738492,
  "&": 530174,
  "*": 129073,
  "(": 413982,
  ")": 790364,
  "-": 209374,
  "_": 618349,
  "+": 472395,
  "=": 985312,
  "{": 273948,
  "}": 650293,
  "[": 391746,
  "]": 482319,
  "|": 537104,
  "\\": 672491,
  ":": 394871,
  ";": 840123,
  "'": 560481,
  "\"": 127983,
  ",": 293807,
  ".": 718409,
  "<": 364091,
  ">": 583201,
  "?": 490127,
  "/": 768203,
  " ": 999999
});

function nativeTokenEncode(value) {
  const parts = [];

  for (const character of String(value || "")) {
    const code = NATIVE_TOKEN_CODES[character];
    if (!Number.isInteger(code)) {
      throw new Error("Legacy libmain token chứa ký tự không được hỗ trợ.");
    }
    parts.push(String(code));
  }

  return parts.join("-");
}

async function legacyKeysSchema(env) {
  const result = await env.DB.prepare("PRAGMA table_info(keys)").all();
  const names = new Set(
    (result.results || []).map(row => String(row.name || ""))
  );

  return {
    deviceHash: names.has("device_hash"),
    claimedAt: names.has("claimed_at"),
    deviceBound: names.has("device_bound"),
    used: names.has("used"),
    maxUses: names.has("max_uses"),
    lastUsedAt: names.has("last_used_at")
  };
}

async function claimNativeDevice(env, key, row, deviceId, hash, now) {
  const schema = await legacyKeysSchema(env);

  // Newer Sent Tweaks schema: reuse the existing hashed multi-device binder.
  if (schema.deviceHash) {
    return claimDeviceForKey(env, key, row, hash, now);
  }

  // Older schema used by the first D1 deployment.
  if (schema.deviceBound) {
    const currentDevice = String(row.device_bound || "").trim();

    if (currentDevice) {
      if (currentDevice !== deviceId) {
        return {
          ok: false,
          error: "Key đã được liên kết với thiết bị khác."
        };
      }

      if (schema.lastUsedAt) {
        await env.DB.prepare(
          `UPDATE keys SET last_used_at = ? WHERE license_key = ?`
        ).bind(now, key).run();
      }

      return { ok: true, row };
    }

    const used = schema.used ? Number(row.used || 0) : 0;
    const maxUses = schema.maxUses ? Number(row.max_uses || 1) : 1;

    if (maxUses > 0 && used >= maxUses) {
      return {
        ok: false,
        error: "Key đã đạt giới hạn thiết bị."
      };
    }

    const sets = ["device_bound = ?"];
    const binds = [deviceId];

    if (schema.used) {
      sets.push("used = used + 1");
    }

    if (schema.lastUsedAt) {
      sets.push("last_used_at = ?");
      binds.push(now);
    }

    binds.push(key);

    const update = await env.DB.prepare(
      `UPDATE keys
       SET ${sets.join(", ")}
       WHERE license_key = ?
         AND status = 'active'
         AND expires_at > ?
         AND (device_bound IS NULL OR device_bound = '')`
    ).bind(...binds, now).run();

    if (!update.meta.changes) {
      const fresh = await env.DB.prepare(
        `SELECT * FROM keys WHERE license_key = ? LIMIT 1`
      ).bind(key).first();

      if (!fresh) {
        return { ok: false, error: "Không tìm thấy key." };
      }

      if (String(fresh.device_bound || "").trim() === deviceId) {
        return { ok: true, row: fresh };
      }

      return {
        ok: false,
        error: "Key đã được liên kết với thiết bị khác."
      };
    }

    const fresh = await env.DB.prepare(
      `SELECT * FROM keys WHERE license_key = ? LIMIT 1`
    ).bind(key).first();

    return { ok: true, row: fresh || row };
  }

  // Fail closed instead of silently accepting a key without device binding.
  return {
    ok: false,
    error: "D1_SCHEMA_UNSUPPORTED"
  };
}

async function handleNativeClaim(request, env) {
  const contentType = String(
    request.headers.get("content-type") || ""
  ).toLowerCase();

  if (contentType.includes("application/json")) {
    return null;
  }

  const rawBody = await request.text();
  const form = new URLSearchParams(rawBody);

  const submittedKey = String(form.get("key") || "").trim();
  const submittedDeviceId = String(form.get("deviceid") || "").trim();

  if (!submittedKey || !submittedDeviceId) {
    return json({
      ok: false,
      valid: false,
      error: "LEGACY_FIELDS_REQUIRED"
    }, 400);
  }

  // Normalize only for D1 lookup. The response token MUST use the exact key
  // string submitted by the native client, because the client calculates the
  // same token locally from its original input.
  const key = normalizeKey(submittedKey);
  const deviceId = normalizeDeviceId(submittedDeviceId);
  const hash = await deviceHash(env, deviceId);
  const now = Date.now();

  const row = await env.DB.prepare(
    `SELECT * FROM keys WHERE license_key = ? LIMIT 1`
  )
    .bind(key)
    .first();

  if (!row) {
    return json({ ok: false, valid: false, error: "Không tìm thấy key." }, 404);
  }

  if (row.status === "revoked") {
    return json({ ok: false, valid: false, error: "Key đã bị thu hồi." }, 403);
  }

  if (now >= Number(row.expires_at)) {
    return json({ ok: false, valid: false, error: "Key đã hết hạn." }, 403);
  }

  const claimResult = await claimNativeDevice(
    env,
    key,
    row,
    deviceId,
    hash,
    now
  );

  if (!claimResult.ok) {
    return json({
      ok: false,
      valid: false,
      error: claimResult.error
    }, 409);
  }

  const token = nativeTokenEncode(
    `meostar-${submittedKey}-${deviceId}`
  );

  return json({
    ok: true,
    valid: true,
    token
  });
}

async function handleClaim(
  request,
  env
) {
  const body =
    await readJson(request);

  const requestMetadata =
    readAuthRequestMetadata(body);

  enforceAuthPolicy(env, requestMetadata);

  const key =
    normalizeKey(body.key);

  const deviceId =
    normalizeDeviceId(
      body.deviceId
    );

  const hash =
    await deviceHash(
      env,
      deviceId
    );

  const now = Date.now();

  const row =
    await env.DB.prepare(
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
        error:
          "Không tìm thấy key."
      },
      404
    );
  }

  if (row.status === "revoked") {
    return json(
      {
        ok: false,
        valid: false,
        error:
          "Key đã bị thu hồi."
      },
      403
    );
  }

  if (
    now >= Number(row.expires_at)
  ) {
    return json(
      {
        ok: false,
        valid: false,
        error:
          "Key đã hết hạn."
      },
      403
    );
  }

  const claimResult =
    await claimDeviceForKey(
      env,
      key,
      row,
      hash,
      now
    );

  if (!claimResult.ok) {
    return json(
      {
        ok: false,
        valid: false,
        error: claimResult.error
      },
      409
    );
  }

  const fresh = claimResult.row;
  const payload = {
    ok: true,
    valid: true,
    data: publicKeyRow(
      fresh,
      now
    )
  };

  return json(
    await withSignedAuthResponse(
      env,
      "/api/claim",
      requestMetadata,
      deviceId,
      payload
    )
  );
}


async function handleDualSchemaClaim(
  request,
  env
) {
  if (request.method !== "POST") {
    return json({ ok: false, valid: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  let originalBody;
  try {
    originalBody = await request.clone().json();
  } catch {
    return json({ ok: false, valid: false, error: "INVALID_JSON" }, 400);
  }

  const normalized = authNormalizeBody(originalBody);
  if (
    !normalized.key ||
    !normalized.deviceId ||
    !normalized.nonce ||
    !normalized.clientTimeMs ||
    normalized.protocolVersion !== AUTH_RESPONSE_PROTOCOL ||
    !normalized.buildId ||
    !normalized.clientVersion
  ) {
    return json({
      ok: false,
      valid: false,
      error: "AUTH_V4_FIELDS_REQUIRED"
    }, 400);
  }

  const headers = new Headers(request.headers);
  headers.set("content-type", "application/json");
  headers.delete("content-length");

  const modernRequest = new Request(request.url, {
    method: "POST",
    headers,
    body: JSON.stringify({
      key: normalized.key,
      deviceId: normalized.deviceId,
      nonce: normalized.nonce,
      clientTimeMs: normalized.clientTimeMs,
      protocolVersion: normalized.protocolVersion,
      buildId: normalized.buildId,
      clientVersion: normalized.clientVersion
    })
  });

  return handleClaim(modernRequest, env);
}

async function handleRevoke(
  request,
  env
) {
  if (!isAdmin(request, env)) {
    return json(
      {
        ok: false,
        error: "Không có quyền."
      },
      401
    );
  }

  const body =
    await readJson(request);

  const key =
    normalizeKey(body.key);

  const result =
    await env.DB.prepare(
      `UPDATE keys
       SET status = 'revoked'
       WHERE license_key = ?`
    )
      .bind(key)
      .run();

  return json({
    ok: true,
    changed:
      result.meta.changes
  });
}


async function route(
  request,
  env,
  ctx
) {
  const url =
    new URL(request.url);

  const path =
    url.pathname;

  if (
    request.method === "GET" &&
    path === "/api/health"
  ) {
    return json({
      ok: true,

      service:
        "Sent Tweaks Get Key",

      database:
        Boolean(env.DB),

      link4m:
        Boolean(
          env.LINK4M_API_TOKEN
        ),

      authSigning:
        Boolean(
          env.AUTH_PRIVATE_KEY_PEM
        ),

      authEnabled:
        authServerEnabled(env),

      authProtocol:
        AUTH_RESPONSE_PROTOCOL,

      activeBuildId:
        authActiveBuildId(env),

      policyGeneration:
        authPolicyGeneration(env)
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
        error:
          "Bạn cần vượt Link4m để nhận key."
      },
      403
    );
  }

  if (
    request.method === "POST" &&
    path === "/api/admin/link4m-stats"
  ) {
    return handleAdminLink4mStats(
      request,
      env
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


  /*
   * Single authentication endpoint for both native form and Auth V4 JSON.
   */
  if (
    request.method === "POST" &&
    path === "/api/claim"
  ) {
    const contentType = String(
      request.headers.get("content-type") || ""
    ).toLowerCase();

    // Native lib uses CURLOPT_POSTFIELDS => form-urlencoded.
    // Auth V4 JSON clients continue through the signed JSON path.
    if (!contentType.includes("application/json")) {
      return handleNativeClaim(
        request,
        env
      );
    }

    return handleDualSchemaClaim(
      request,
      env,
      ctx
    );
  }


  if (
    request.method === "POST" &&
    path === "/api/admin/revoke"
  ) {
    return handleRevoke(
      request,
      env
    );
  }

  if (
    request.method === "GET" &&
    (
      path === "/senttwgetkey" ||
      path === "/senttwnhankey"
    )
  ) {
    return handleLink4mLanding(
      request,
      env
    );
  }

  if (
    path.startsWith("/api/")
  ) {
    return json(
      {
        ok: false,
        error:
          "Không tìm thấy API."
      },
      404
    );
  }

  return env.ASSETS.fetch(
    request
  );
}

export default {
  async fetch(
    request,
    env,
    ctx
  ) {
    try {
      return await route(
        request,
        env,
        ctx
      );
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


      


  

  
