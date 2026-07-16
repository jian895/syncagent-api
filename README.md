# SyncAgent API

智能体配置云同步 - 后端 API

## 技术栈

- **框架**: FastAPI
- **协议**: MCP (Model Context Protocol)
- **认证**: JWT
- **部署**: Railway

## 本地开发

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置环境变量

创建 `.env` 文件：

```bash
JWT_SECRET=your-secret-key-here
ENV=development
DATABASE_URL=postgresql://...  # 可选，暂时用内存存储
```

### 3. 启动服务

```bash
# 开发模式（自动重载）
uvicorn main:app --reload --port 8000

# 或直接运行
python main.py
```

访问：
- API: http://localhost:8000
- 文档: http://localhost:8000/docs
- MCP 端点: http://localhost:8000/mcp

## 部署到 Railway

### 方法1：通过 Git（推荐）

```bash
# 1. 推送到 GitHub
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/你的用户名/syncagent-api.git
git push -u origin main

# 2. 在 Railway 导入
访问 https://railway.app
点击 "New Project"
选择 "Deploy from GitHub repo"
选择 syncagent-api 仓库
```

### 方法2：使用 Railway CLI

```bash
# 安装 Railway CLI
npm i -g @railway/cli

# 登录
railway login

# 初始化项目
railway init

# 部署
railway up
```

### 配置环境变量

在 Railway Dashboard：
1. 进入项目
2. 点击 "Variables"
3. 添加：
   ```
   JWT_SECRET=随机生成的密钥
   ENV=production
   ```

## API 端点

### 认证

- `POST /auth/register` - 发送验证码
- `POST /auth/verify` - 验证验证码并获取 Token

### MCP

- `POST /mcp` - MCP 协议端点
  - 支持 `initialize`、`tools/list`、`tools/call`

### 健康检查

- `GET /` - API 信息
- `GET /health` - 健康状态

## MCP 工具

当前实现的工具：

1. **syncagent_backup** - 备份配置（开发中）
2. **syncagent_restore** - 恢复配置（开发中）
3. **syncagent_status** - 查看状态（已实现）

## 项目结构

```
syncagent-api/
├── main.py                 # FastAPI 主文件
├── requirements.txt        # Python 依赖
├── Procfile                # Railway 启动命令
├── .env                    # 环境变量（本地，不提交）
├── .gitignore
└── README.md
```

## 开发路线图

- [x] 基础认证（邮箱验证码）
- [x] JWT Token 生成
- [x] MCP 协议框架
- [x] 客户端检测
- [ ] 实际的备份/恢复逻辑
- [ ] 数据库集成（Supabase）
- [ ] 对象存储集成（Cloudflare R2）
- [ ] 邮件发送（SendGrid）
- [ ] 配置转换引擎

## 测试

```bash
# 测试认证
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'

# 测试 MCP
curl -X POST http://localhost:8000/mcp \
  -H "Authorization: Bearer your_token_here" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

## 注意事项

- 当前使用内存存储，重启后数据丢失
- 生产环境需要配置实际的数据库和对象存储
- `ENV=development` 时会返回验证码（方便测试）
- 记得修改 `JWT_SECRET` 为强随机字符串

## License

MIT
