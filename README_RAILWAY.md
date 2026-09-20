# Move To Blue License API — Railway

Đây là backend đã chỉnh để chạy trực tiếp trên Railway.

## Railway Variables

Tạo các Variables:

- `ADMIN_USER=admin`
- `ADMIN_PASSWORD=<mật khẩu admin mạnh>`
- `TOOL_NAME=Move To Blue`
- `ALLOWED_ORIGINS=https://lecongminhvuong31154-hash.github.io`
- `DB_PATH=/data/license_manager.db`

Không cần tự tạo `PORT`: Railway cung cấp biến này.

## Volume

Thêm Volume cho service và mount tại:

`/data`

Database SQLite sẽ nằm tại:

`/data/license_manager.db`

## Domain

Trong Railway:

Settings -> Networking -> Generate Domain

Sau đó test:

`https://<domain>.up.railway.app/api/health`

## GitHub Pages

Trong `api-config.js`:

```js
window.APP_CONFIG = {
  API_BASE_URL: "https://<domain>.up.railway.app",
  API_TIMEOUT_MS: 8000
};
```

## Launcher

Trong `client/config.json`:

```json
{
  "public_server_url": "https://<domain>.up.railway.app"
}
```
