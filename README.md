# Sent Tweaks Auth — safe migration

## What this package does

This Worker keeps authentication enforced by D1. It supports:

- GET and POST
- JSON
- application/x-www-form-urlencoded
- query-string parameters
- key aliases:
  - key
  - licenseKey
  - license_key
  - userKey
  - user_key
  - code
- device aliases:
  - deviceId
  - device_id
  - androidId
  - android_id
  - stableDeviceId
  - stable_device_id
  - device
- endpoint aliases:
  - /api/claim
  - /auth
  - /login
  - /license/claim
  - /api/verify
  - /verify
  - /license/verify

## Recommended migration path

The safest way to keep the protected Android binary working is to preserve the
old hostname and route it to this Worker.

If you control the old domain:

1. Add the old hostname as a Cloudflare Worker custom domain or route.
2. Point its proxied DNS record to Cloudflare.
3. Keep the original hostname and path expected by the client.
4. Deploy this Worker behind that hostname.

This avoids binary patching, TLS interception, certificate problems, and
Virbox runtime modification.

If you do not control the old hostname, update the endpoint in the original
client source and rebuild the app. A protected binary should not be modified
through TLS hooks or anti-instrumentation bypasses.

## Install and deploy

```bash
npm install
npx wrangler d1 migrations apply DB --remote
npx wrangler deploy
```

Before running those commands, replace the D1 `database_id` inside
`wrangler.toml`.

## Create a test key

Replace the expiry timestamp with a future Unix timestamp.

```bash
npx wrangler d1 execute DB --remote --command "
INSERT INTO keys (
  license_key,
  status,
  expires_at,
  device_bound,
  used,
  max_uses,
  created_at
) VALUES (
  'SENT-TEST-001',
  'active',
  1893456000,
  NULL,
  0,
  1,
  strftime('%s','now')
);
"
```

## Test claim

```bash
curl -X POST \
  "https://YOUR-WORKER.workers.dev/api/claim" \
  -H "Content-Type: application/json" \
  -d '{"key":"SENT-TEST-001","deviceId":"device-001"}'
```

## Test verify

```bash
curl -X POST \
  "https://YOUR-WORKER.workers.dev/api/verify" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "license_key=SENT-TEST-001&device_id=device-001"
```

## Common failure reasons

- `INVALID_KEY`: key is absent from D1
- `KEY_INACTIVE`: status is not `active`
- `KEY_EXPIRED`: expiry is in the past
- `DEVICE_MISMATCH`: key is already bound to another device
- `KEY_ALREADY_USED`: maximum allowed activations was reached
- `MISSING_KEY`: field name does not match a supported alias
- `MISSING_DEVICE_ID`: no supported device field was sent
