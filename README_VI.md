# Sent Tweaks Get Key — Cloudflare Workers + D1

Bản này chạy trên Cloudflare Workers, dùng D1 để lưu key và không đọc/lưu IP.
Device ID được băm SHA-256 trước khi lưu; mỗi key chỉ gắn với một thiết bị.

## 1. Chuẩn bị

- Tạo tài khoản Cloudflare.
- Cài Node.js trên máy tính hoặc dùng môi trường có terminal.
- Giải nén source và mở terminal trong thư mục này.

```bash
npm install
npx wrangler login
```

## 2. Tạo D1

```bash
npx wrangler d1 create senttweaks-getkey-db
```

Lệnh sẽ trả về `database_id`. Mở `wrangler.jsonc` và thay:

```text
REPLACE_WITH_YOUR_D1_DATABASE_ID
```

bằng ID thật.

## 3. Tạo bảng

```bash
npm run db:remote
```

## 4. Thiết lập bí mật

```bash
npx wrangler secret put ADMIN_TOKEN
npx wrangler secret put DEVICE_SALT
```

Nhập hai chuỗi dài, khác nhau. Không đưa chúng lên GitHub.

## 5. Chạy thử và deploy

```bash
npm run dev
npm run deploy
```

Sau khi deploy, Cloudflare cung cấp địa chỉ dạng `*.workers.dev`.

## API chính

### Tạo key bằng quyền quản trị

`POST /api/admin/create-key`

Header:

```text
Authorization: Bearer YOUR_ADMIN_TOKEN
Content-Type: application/json
```

Body:

```json
{"planHours":12}
```

### Kích hoạt key lần đầu

`POST /api/claim`

```json
{"key":"SENT-XXXXX-XXXXX-XXXXX","deviceId":"DEVICE-ID"}
```

### Kiểm tra key

`POST /api/verify`

```json
{"key":"SENT-XXXXX-XXXXX-XXXXX","deviceId":"DEVICE-ID"}
```

## Chế độ thử nghiệm

`DEMO_MODE` đang là `true`, nên hai nút 12H/24H trên web tạo key trực tiếp để kiểm tra.
Trước khi dùng thật, đổi thành `false` trong `wrangler.jsonc`.

## Link4M

Hai đường dẫn callback đã giữ theo yêu cầu:

- `/senttwgetkey`
- `/senttwnhankey`

Hiện chúng chỉ chuyển về trang chủ. Để chống người dùng bỏ qua Link4M, cần thông tin API/callback xác thực thật từ tài khoản Link4M; không nên chỉ kiểm tra một URL tĩnh.
