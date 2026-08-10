// Sent Tweaks compatibility entry.
// It upgrades older JSON clients to the signed Auth V4 request shape,
// then delegates all real validation to index.js (D1, expiry, device binding, signatures).
import signedWorker from "./index.js";

const AUTH_PROTOCOL_VERSION = 4;
const DEFAULT_BUILD_ID = "sent-menu-2026.08.07-r1";
const DEFAULT_CLIENT_VERSION = "5.2.1";

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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

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
