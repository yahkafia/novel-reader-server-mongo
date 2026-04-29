# NovelReader Account Server

MongoDB 版本后端，适合部署到腾讯云轻量应用服务器。

## 环境变量

复制 `.env.example` 为 `.env`，至少配置：

- `MONGO_URI`
- `MONGO_DATABASE`
- `TOKEN_SECRET`
- `PORT`

## Docker Compose 部署

```bash
docker compose up -d --build
curl http://127.0.0.1:3000/health
```

## 导入 CloudBase 导出的 users.json

把 `users.json` 放到项目根目录后执行：

```bash
docker exec -i novel-reader-server node scripts/import-cloudbase-users.js /app/users.json
```

或者在本地/服务器 Node 环境中执行：

```bash
MONGO_URI='mongodb://root:password@127.0.0.1:27017/novel_reader?authSource=admin' node scripts/import-cloudbase-users.js users.json
```
