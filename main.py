from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
import jwt
import os
from datetime import datetime, timedelta
import random
import json
import urllib.request
import urllib.parse

app = FastAPI(title="SyncAgent API", version="1.0.0")

# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 生产环境应该限制具体域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 配置（从环境变量读取）
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
DATABASE_URL = os.getenv("DATABASE_URL", "")

# 临时存储（生产环境应该用数据库）
verification_codes = {}  # {email: {"code": "123456", "expires": timestamp}}
users = {}  # {user_id: {"email": "...", "created_at": "..."}}
configs = {}  # {user_id: {client_type: config_data}}

# ============= Pydantic 模型 =============

class RegisterRequest(BaseModel):
    email: EmailStr

class VerifyRequest(BaseModel):
    email: EmailStr
    code: str

class TokenResponse(BaseModel):
    token: str
    user_id: str

class GoogleAuthRequest(BaseModel):
    credential: str  # Google Identity Services 返回的 ID token (JWT)

# ============= 认证相关 API =============

@app.post("/auth/register")
async def register(request: RegisterRequest):
    """发送验证码到邮箱"""
    email = request.email
    
    # 生成6位验证码
    code = str(random.randint(100000, 999999))
    
    # 保存验证码（5分钟有效）
    verification_codes[email] = {
        "code": code,
        "expires": datetime.now() + timedelta(minutes=5)
    }
    
    # TODO: 实际发送邮件（使用 SendGrid 或阿里云邮件推送）
    print(f"📧 验证码发送到 {email}: {code}")
    
    # 开发环境：直接返回验证码（生产环境删除此行）
    if os.getenv("ENV") == "development":
        return {"message": "验证码已发送", "code": code}
    
    return {"message": "验证码已发送"}

@app.post("/auth/verify", response_model=TokenResponse)
async def verify(request: VerifyRequest):
    """验证验证码并返回 Token"""
    email = request.email
    code = request.code
    
    # 检查验证码是否存在
    if email not in verification_codes:
        raise HTTPException(status_code=400, detail="验证码不存在或已过期")
    
    stored = verification_codes[email]
    
    # 检查是否过期
    if datetime.now() > stored["expires"]:
        del verification_codes[email]
        raise HTTPException(status_code=400, detail="验证码已过期")
    
    # 验证验证码
    if stored["code"] != code:
        raise HTTPException(status_code=400, detail="验证码错误")
    
    # 验证成功，删除验证码
    del verification_codes[email]
    
    # 创建或获取用户
    user_id = None
    for uid, user in users.items():
        if user["email"] == email:
            user_id = uid
            break
    
    if not user_id:
        user_id = f"user_{len(users) + 1}"
        users[user_id] = {
            "email": email,
            "created_at": datetime.now().isoformat()
        }
    
    # 生成 JWT Token
    token_payload = {
        "user_id": user_id,
        "email": email,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=365)  # 1年有效期
    }
    token = jwt.encode(token_payload, JWT_SECRET, algorithm="HS256")
    
    return TokenResponse(token=token, user_id=user_id)

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")

def _issue_token(user_id, email):
    """签发 SyncAgent 自己的 JWT"""
    payload = {
        "user_id": user_id,
        "email": email,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=365),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def _get_or_create_user(email):
    for uid, user in users.items():
        if user["email"] == email:
            return uid
    user_id = f"user_{len(users) + 1}"
    users[user_id] = {"email": email, "created_at": datetime.now().isoformat()}
    return user_id

@app.post("/auth/google", response_model=TokenResponse)
async def auth_google(request: GoogleAuthRequest):
    """用 Google 登录：验证 Google ID token，签发 SyncAgent Token"""
    credential = request.credential

    # 通过 Google tokeninfo 端点验证 ID token（无需额外依赖）
    try:
        url = "https://oauth2.googleapis.com/tokeninfo?" + urllib.parse.urlencode({"id_token": credential})
        with urllib.request.urlopen(url, timeout=10) as resp:
            info = json.loads(resp.read().decode())
    except Exception:
        raise HTTPException(status_code=401, detail="无法验证 Google 登录凭证")

    # 校验 audience（如果配置了 GOOGLE_CLIENT_ID）
    if GOOGLE_CLIENT_ID and info.get("aud") != GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=401, detail="Google 凭证的 client id 不匹配")

    # 校验签发方
    if info.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        raise HTTPException(status_code=401, detail="Google 凭证签发方无效")

    email = info.get("email")
    if not email or info.get("email_verified") not in ("true", True):
        raise HTTPException(status_code=401, detail="Google 账号邮箱未验证")

    user_id = _get_or_create_user(email)
    token = _issue_token(user_id, email)
    return TokenResponse(token=token, user_id=user_id)

# ============= 辅助函数 =============

def verify_token(authorization: str) -> str:
    """验证 Token 并返回 user_id"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="未提供认证 Token")
    
    token = authorization.replace("Bearer ", "")
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token 已过期")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="无效的 Token")

def detect_client_from_mcp_init(client_info: Dict[str, Any]) -> str:
    """从 MCP initialize 消息检测客户端类型"""
    name = client_info.get("name", "").lower()
    
    mapping = {
        "reasonix": "reasonix",
        "cursor": "cursor",
        "cline": "cursor",
        "claude": "claude_desktop",
        "claude-desktop": "claude_desktop",
        "windsurf": "windsurf",
    }
    
    for key, value in mapping.items():
        if key in name:
            return value
    
    return "unknown"


# ============= MCP 工具定义 =============

MCP_TOOLS = [
    {
        "name": "syncagent_backup",
        "description": "备份当前智能体配置到云端",
        "inputSchema": {
            "type": "object",
            "properties": {
                "client_type": {
                    "type": "string",
                    "description": "智能体类型，如 reasonix / cursor / claude_desktop",
                },
                "config": {
                    "type": "object",
                    "description": "要备份的配置内容（MCP 配置、技能、记忆等）",
                },
            },
            "required": ["client_type", "config"],
        },
    },
    {
        "name": "syncagent_restore",
        "description": "从云端恢复配置",
        "inputSchema": {
            "type": "object",
            "properties": {
                "from_client": {
                    "type": "string",
                    "description": "从哪个客户端恢复（可选，默认返回全部）",
                }
            },
        },
    },
    {
        "name": "syncagent_status",
        "description": "查看云端配置状态",
        "inputSchema": {"type": "object", "properties": {}},
    },
]

SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")


def _extract_bearer_user(authorization: Optional[str]) -> Optional[str]:
    """从 Authorization 头解析 user_id，失败返回 None（不抛异常）。"""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization[len("Bearer "):]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload.get("user_id")
    except jwt.PyJWTError:
        return None


def _jsonrpc_result(msg_id, result):
    return JSONResponse({"jsonrpc": "2.0", "id": msg_id, "result": result})


def _jsonrpc_error(msg_id, code, message):
    return JSONResponse(
        {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}
    )


def _handle_tool_call(user_id, params):
    """执行工具调用，返回 result dict。"""
    tool_name = params.get("name")
    arguments = params.get("arguments", {}) or {}

    if tool_name == "syncagent_backup":
        client_type = arguments.get("client_type", "unknown")
        config = arguments.get("config", {})
        user_configs = configs.setdefault(user_id, {})
        user_configs[client_type] = {
            "config": config,
            "synced_at": datetime.now().isoformat(),
        }
        text = f"✓ 已备份 {client_type} 配置到云端（{user_configs[client_type]['synced_at']}）"

    elif tool_name == "syncagent_restore":
        from_client = arguments.get("from_client")
        user_configs = configs.get(user_id, {})
        if not user_configs:
            text = "云端暂无配置，无法恢复。"
        elif from_client:
            entry = user_configs.get(from_client)
            if not entry:
                text = f"云端没有 {from_client} 的配置。"
            else:
                text = json.dumps(entry["config"], ensure_ascii=False)
        else:
            text = json.dumps(
                {ct: e["config"] for ct, e in user_configs.items()},
                ensure_ascii=False,
            )

    elif tool_name == "syncagent_status":
        user_configs = configs.get(user_id, {})
        if not user_configs:
            text = "云端暂无配置"
        else:
            lines = ["云端配置："]
            for client_type, entry in user_configs.items():
                lines.append(f"- {client_type}（{entry.get('synced_at', '未知')}）")
            text = "\n".join(lines)
    else:
        return None  # 未知工具

    return {"content": [{"type": "text", "text": text}], "isError": False}


# ============= MCP Server (Streamable HTTP) =============


@app.get("/mcp")
async def mcp_get():
    # 本服务器为同步请求/响应模式，不提供 SSE 流
    return Response(status_code=405)


@app.post("/mcp")
async def mcp_endpoint(request: Request, authorization: Optional[str] = Header(None)):
    """MCP Streamable HTTP 端点（application/json 请求/响应模式）。"""
    try:
        body = await request.json()
    except Exception:
        return _jsonrpc_error(None, -32700, "Parse error")

    # 通知或响应消息（没有 id）→ 202 Accepted，无 body
    if not isinstance(body, dict) or "id" not in body:
        return Response(status_code=202)

    msg_id = body.get("id")
    method = body.get("method")
    params = body.get("params", {}) or {}

    # initialize 不需要鉴权（握手阶段）
    if method == "initialize":
        client_ver = params.get("protocolVersion", "2025-06-18")
        negotiated = client_ver if client_ver in SUPPORTED_PROTOCOL_VERSIONS else "2025-06-18"
        return _jsonrpc_result(
            msg_id,
            {
                "protocolVersion": negotiated,
                "serverInfo": {"name": "syncagent", "version": "1.0.0"},
                "capabilities": {"tools": {"listChanged": False}},
            },
        )

    if method == "ping":
        return _jsonrpc_result(msg_id, {})

    # 其余方法需要有效 Token
    user_id = _extract_bearer_user(authorization)
    if not user_id:
        return _jsonrpc_error(msg_id, -32001, "未认证：缺少或无效的 Token")

    if method == "tools/list":
        return _jsonrpc_result(msg_id, {"tools": MCP_TOOLS})

    if method == "tools/call":
        result = _handle_tool_call(user_id, params)
        if result is None:
            return _jsonrpc_error(msg_id, -32602, f"未知工具：{params.get('name')}")
        return _jsonrpc_result(msg_id, result)

    return _jsonrpc_error(msg_id, -32601, f"Method not found: {method}")


# ============= 健康检查 =============

@app.get("/")
async def root():
    return {
        "name": "SyncAgent API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
