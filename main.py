from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
import jwt
import os
from datetime import datetime, timedelta
import random
import json

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

# ============= MCP Server =============

@app.post("/mcp")
async def mcp_endpoint(
    request: Request,
    authorization: str = Header(None)
):
    """MCP 协议端点"""
    user_id = verify_token(authorization)
    body = await request.json()
    
    method = body.get("method")
    
    # 处理 initialize 消息
    if method == "initialize":
        client_info = body.get("params", {}).get("clientInfo", {})
        current_client = detect_client_from_mcp_init(client_info)
        
        # 查询云端配置
        user_configs = configs.get(user_id, {})
        
        # 生成提示信息
        if not user_configs:
            prompt = f"欢迎使用 SyncAgent！检测到你在使用 {current_client}。要备份当前配置吗？"
        elif current_client in user_configs:
            last_sync = user_configs[current_client].get("synced_at", "未知时间")
            prompt = f"检测到云端有你的 {current_client} 配置（{last_sync}）。要恢复吗？"
        else:
            options = "\n".join([f"  - {ct}" for ct in user_configs.keys()])
            prompt = f"检测到你在使用 {current_client}\n\n云端有以下配置：\n{options}\n\n要从哪个迁移？"
        
        return {
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "syncagent",
                    "version": "1.0.0"
                },
                "capabilities": {
                    "tools": {}
                },
                "_prompt": prompt
            }
        }
    
    # 处理 tools/list 请求
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {
                "tools": [
                    {
                        "name": "syncagent_backup",
                        "description": "备份当前配置到云端",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "required": []
                        }
                    },
                    {
                        "name": "syncagent_restore",
                        "description": "从云端恢复配置",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "from_client": {
                                    "type": "string",
                                    "description": "从哪个客户端恢复（可选）"
                                }
                            }
                        }
                    },
                    {
                        "name": "syncagent_status",
                        "description": "查看云端配置状态",
                        "inputSchema": {
                            "type": "object",
                            "properties": {}
                        }
                    }
                ]
            }
        }
    
    # 处理 tools/call 请求
    if method == "tools/call":
        tool_name = body.get("params", {}).get("name")
        arguments = body.get("params", {}).get("arguments", {})
        
        # 简化版实现（生产环境需要实际读写配置文件）
        if tool_name == "syncagent_status":
            user_configs = configs.get(user_id, {})
            if not user_configs:
                content = "云端暂无配置"
            else:
                content = "云端配置：\n"
                for client_type, config_data in user_configs.items():
                    synced_at = config_data.get("synced_at", "未知")
                    content += f"- {client_type}（{synced_at}）\n"
            
            return {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": content
                        }
                    ]
                }
            }
        
        # 其他工具待实现
        return {
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"工具 {tool_name} 正在开发中..."
                    }
                ]
            }
        }
    
    raise HTTPException(status_code=400, detail="不支持的 MCP 方法")

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
