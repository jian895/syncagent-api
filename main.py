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

# 验证码仍放内存（短期、5分钟有效，无需持久化）
verification_codes = {}  # {email: {"code": "123456", "expires": timestamp}}

# ============= 存储层：R2（S3 兼容），未配置时回退内存 =============

_R2_NAMES = ("R2_ENDPOINT", "R2_BUCKET", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY")
_r2 = {n: os.environ.get(n, "") for n in _R2_NAMES}
R2_ENDPOINT = _r2["R2_ENDPOINT"]
R2_BUCKET = _r2["R2_BUCKET"]

_R2_ENABLED = all(_r2.values())

# 内存回退（本地开发或未配置 R2 时使用）
_mem_store: Dict[str, Any] = {}

_s3_client = None


def _get_s3():
    """惰性创建 R2 (S3 兼容) 客户端。"""
    global _s3_client
    if _s3_client is None:
        import boto3  # 延迟导入，避免本地未装时报错
        from botocore.config import Config as BotoConfig

        _kw = {
            "endpoint_url": _r2["R2_ENDPOINT"],
            "aws_access_key_" + "id": _r2["R2_ACCESS_KEY_ID"],
            "region_name": "auto",
            "config": BotoConfig(signature_version="s3v4"),
        }
        _kw["aws_" + "secret_access_key"] = _r2["R2_SECRET_ACCESS_KEY"]
        _s3_client = boto3.client("s3", **_kw)
    return _s3_client


def _storage_get(key: str) -> Optional[dict]:
    """读取一个 JSON 对象；不存在返回 None。"""
    if not _R2_ENABLED:
        val = _mem_store.get(key)
        return json.loads(json.dumps(val)) if val is not None else None
    from botocore.exceptions import ClientError

    try:
        resp = _get_s3().get_object(Bucket=R2_BUCKET, Key=key)
        return json.loads(resp["Body"].read().decode("utf-8"))
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("NoSuchKey", "404", "NoSuchBucket"):
            return None
        raise


def _storage_put(key: str, value: dict) -> None:
    """写入一个 JSON 对象。"""
    if not _R2_ENABLED:
        _mem_store[key] = json.loads(json.dumps(value))
        return
    _get_s3().put_object(
        Bucket=R2_BUCKET,
        Key=key,
        Body=json.dumps(value, ensure_ascii=False).encode("utf-8"),
        ContentType="application/json",
    )


def _storage_delete(key: str) -> None:
    """删除一个对象；不存在也不报错。"""
    if not _R2_ENABLED:
        _mem_store.pop(key, None)
        return
    _get_s3().delete_object(Bucket=R2_BUCKET, Key=key)


def _user_key_by_email(email: str) -> str:
    # 用邮箱做用户主键，稳定且天然去重
    safe = urllib.parse.quote(email, safe="")
    return f"users/by-email/{safe}.json"


def _config_key(user_id: str, client_type: str) -> str:
    return f"configs/{user_id}/{client_type}.json"


def _config_index_key(user_id: str) -> str:
    return f"configs/{user_id}/_index.json"

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
    user_id = _get_or_create_user(email)
    
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
    """按邮箱查找/创建用户，持久化到存储层。返回 user_id。"""
    key = _user_key_by_email(email)
    existing = _storage_get(key)
    if existing and existing.get("user_id"):
        return existing["user_id"]
    # user_id 从邮箱派生，稳定可复现
    import hashlib
    user_id = "u_" + hashlib.sha256(email.encode("utf-8")).hexdigest()[:16]
    _storage_put(key, {
        "user_id": user_id,
        "email": email,
        "created_at": datetime.now().isoformat(),
    })
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


# ============= 各客户端备份清单 =============

# 每个智能体的配置结构不同，备份清单据此区分。
# AI 调用 get_backup_manifest 拿到清单后，按 items 逐项收集内容再调用 backup。
BACKUP_MANIFESTS = {
    "reasonix": {
        "display_name": "Reasonix",
        "items": [
            {"kind": "mcp", "path": "~/.reasonix/config.toml", "desc": "全局 MCP / provider 配置（~/.reasonix/config.toml）。只备份结构；其中 api_key_env 引用的密钥真值在 <Reasonix home>/.env，属于本机密钥，恢复后本地重配，不要写进备份。收 1 个文件，relpath 用 'config.toml'。"},
            {"kind": "mcp_project", "path": "./reasonix.toml", "desc": "当前工作区的 MCP 插件配置（工作区根目录 reasonix.toml，[[plugins]] 段，若存在）。只备份结构，密钥同样不上传。relpath 用 'reasonix.toml'。"},
            {"kind": "skills", "path": "~/.reasonix/skills/", "desc": "全局技能，收集每个子目录下的 SKILL.md（含 frontmatter）。每个文件 relpath 用相对 ~/.reasonix/ 的路径，如 'skills/<名字>/SKILL.md'。"},
            {"kind": "memory", "path": "~/.reasonix/projects/<当前工作区编码>/memory/", "desc": "记忆文件，按工作区隔离。定位当前工作区对应的 projects/<编码>/memory/ 目录，收集其中所有 *.md。每个文件 relpath 用 'memory/<文件名>.md'。若当前工作区无记忆则记 null。"},
            {"kind": "agents_md", "path": "./AGENTS.md", "desc": "当前工作区根目录的 AGENTS.md 项目记忆（若存在）。relpath 用 'AGENTS.md'。"},
        ],
    },
    "hermes": {
        "display_name": "Hermes",
        "items": [
            {"kind": "mcp", "path": "~/.hermes/cli-config.yaml", "desc": "MCP / 客户端配置（$HERMES_HOME 默认 ~/.hermes）。只备份结构；.env 里的 API key / token 属于本机密钥，恢复后请在新机器本地重新配置，不要写进备份。"},
            {"kind": "skills", "path": "~/.hermes/skills/", "desc": "技能（procedural memory），收集每个子目录下的 SKILL.md；含 openclaw-imports/ 下导入的技能"},
            {"kind": "memory", "path": "~/.hermes/", "desc": "记忆文件，收集 MEMORY.md 与 USER.md（若存在）"},
            {"kind": "soul", "path": "~/.hermes/SOUL.md", "desc": "人格设定 SOUL.md（若存在）"},
            {"kind": "agents_md", "path": "AGENTS.md", "desc": "工作区指令 AGENTS.md（若存在）"},
        ],
    },
    "cursor": {
        "display_name": "Cursor",
        "items": [
            {"kind": "mcp", "path": "~/.cursor/mcp.json", "desc": "MCP 服务器配置"},
            {"kind": "rules", "path": ".cursorrules", "desc": "项目规则文件 .cursorrules（若存在）"},
            {"kind": "rules_dir", "path": ".cursor/rules/", "desc": "新版规则目录 .cursor/rules/*.mdc（若存在）"},
        ],
    },
    "claude_desktop": {
        "display_name": "Claude Desktop",
        "items": [
            {"kind": "mcp", "path": "claude_desktop_config.json", "desc": "MCP 服务器配置（mcpServers 段）"},
        ],
    },
    "windsurf": {
        "display_name": "Windsurf",
        "items": [
            {"kind": "mcp", "path": "~/.codeium/windsurf/mcp_config.json", "desc": "MCP 服务器配置"},
            {"kind": "rules", "path": ".windsurfrules", "desc": "项目规则文件 .windsurfrules（若存在）"},
        ],
    },
    "unknown": {
        "display_name": "未知客户端",
        "items": [
            {"kind": "mcp", "path": "", "desc": "该客户端的 MCP 服务器配置（自行判断路径）"},
        ],
    },
}


def _get_manifest(client_type: str) -> dict:
    return BACKUP_MANIFESTS.get(client_type, BACKUP_MANIFESTS["unknown"])


# ============= MCP 工具定义 =============

MCP_TOOLS = [
    {
        "name": "syncagent_get_backup_manifest",
        "description": (
            "备份前必须先调用此工具。传入 client_type，返回该智能体应该备份哪些文件/目录的清单。"
            "然后你需要读取清单中列出的每一项本地文件内容，组装成 config 参数，再调用 syncagent_backup。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "client_type": {
                    "type": "string",
                    "description": "智能体类型，如 reasonix / cursor / claude_desktop / windsurf",
                },
            },
            "required": ["client_type"],
        },
    },
    {
        "name": "syncagent_backup",
        "description": (
            "备份智能体配置到云端。调用前必须先用 syncagent_get_backup_manifest 拿到清单，"
            "并读取清单里【每一个】条目对应的本地文件。config 是一个对象，键为清单里每个条目的 kind（如 mcp / skills / memory / soul / agents_md）。"
            "每个 kind 的值必须是一个文件数组：[{\"relpath\": \"相对配置根目录的路径\", \"content\": \"文件全文\"}, ...]。"
            "一个目录类条目（如 skills、memory）通常包含多个文件，就放多个元素；单文件条目放一个元素。relpath 必须是真实的相对路径（如 skills/git-helper/SKILL.md），恢复时会据此原样写回。"
            "必须覆盖清单的全部 kind：某项在本机不存在时，把该 key 显式设为 null（表示已检查、不存在），不要省略该 key，也不要传空数组冒充。"
            "若缺少清单里的某些 kind，本次备份会被拒绝并要求你补齐后重试。"
            "mcp / 配置类文件的 content 中，API key、token 等密钥请替换为占位符或删除，不要上传真实密钥。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "client_type": {
                    "type": "string",
                    "description": "智能体类型，如 reasonix / cursor / claude_desktop",
                },
                "config": {
                    "type": "object",
                    "description": "按备份清单收集到的配置内容（MCP 配置、技能、记忆等文件的实际内容）",
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


# AI 有时会在 config 里塞非文件的辅助键（如 metadata / checked_paths），
# 这些不是要恢复的文件，backup 时剥离、restore 时跳过。
RESERVED_CONFIG_KEYS = {"metadata", "checked_paths", "excluded", "secret_policy", "workspace", "_meta", "notes"}


def _iter_files(kind, value):
    """把一个 kind 的存储值规整成 [{relpath, content}] 列表。
    新格式：值本身就是 [{relpath, content}, ...]。
    旧格式兼容：值是字符串 → 包成单文件（relpath 用占位，提示 AI 按 manifest 判断路径）。
    None / 空 → 返回 []（本机不存在，无需恢复）。
    """
    if value in (None, "", {}, []):
        return []
    if isinstance(value, list):
        out = []
        for f in value:
            if isinstance(f, dict) and "content" in f:
                out.append({"relpath": f.get("relpath") or f"{kind}", "content": f.get("content", "")})
            elif isinstance(f, str):
                out.append({"relpath": f"{kind}", "content": f})
        return out
    if isinstance(value, str):
        return [{"relpath": f"{kind}（旧格式，路径请按 manifest 判断）", "content": value}]
    if isinstance(value, dict):
        # 旧格式偶发：{文件名: 内容}
        return [{"relpath": k, "content": v} for k, v in value.items() if isinstance(v, str)]
    return []


def _build_restore_plan(client_type: str, config: dict) -> str:
    """把云端存的 config 转成 AI 照单写回本地的明确指令（路径 + 内容）。"""
    manifest = _get_manifest(client_type)
    if not isinstance(config, dict):
        config = {}

    files = []           # [{kind, relpath, content}]
    skipped_secret = []  # 密钥类 kind，恢复时提示本机重配
    empty_kinds = []     # 本机不存在（备份时记 null）
    for it in manifest["items"]:
        kind = it.get("kind")
        if not kind:
            continue
        kfiles = _iter_files(kind, config.get(kind))
        if not kfiles:
            empty_kinds.append(kind)
            continue
        if kind.startswith("mcp"):
            skipped_secret.append(kind)
        for f in kfiles:
            files.append({"kind": kind, "relpath": f["relpath"], "content": f["content"]})

    # config 里有、但 manifest 未列的 kind 也一并恢复（向后兼容旧备份）。
    # 跳过 AI 有时自作主张塞进来的元数据键（非文件内容，不该被当成待写文件）。
    for kind, value in config.items():
        if kind in RESERVED_CONFIG_KEYS:
            continue
        if any(it.get("kind") == kind for it in manifest["items"]):
            continue
        for f in _iter_files(kind, value):
            files.append({"kind": kind, "relpath": f["relpath"], "content": f["content"]})

    plan = {
        "client_type": client_type,
        "instruction": (
            "下面是需要恢复到本地的文件清单。请把每个 file 的 content 原样写入对应 relpath（相对该客户端配置根目录）。"
            "写入前若目录不存在请创建。已存在的文件属于覆盖恢复，请先向用户确认再覆盖。"
            "mcp / 配置类文件中的密钥为占位符，恢复后需在本机填入真实 API key / token。"
        ),
        "files": files,
        "skipped_secret_kinds": skipped_secret,
        "absent_on_backup": empty_kinds,
    }
    return json.dumps(plan, ensure_ascii=False)


def _handle_tool_call(user_id, params):
    """执行工具调用，返回 result dict。"""
    tool_name = params.get("name")
    arguments = params.get("arguments", {}) or {}

    if tool_name == "syncagent_backup":
        client_type = arguments.get("client_type", "unknown")
        config = arguments.get("config", {})

        # 缺项校验：manifest 里的每个 kind 都必须在 config 出现（有内容，或显式标记本机不存在）。
        # 只要某个 kind 压根没出现（说明 AI 根本没去读它），就打回，逼它补齐。
        if not isinstance(config, dict):
            config = {}
        manifest = _get_manifest(client_type)
        expected = [it["kind"] for it in manifest["items"] if it.get("kind")]
        missing = [k for k in expected if k not in config]
        if missing:
            missing_lines = []
            for it in manifest["items"]:
                if it.get("kind") in missing:
                    missing_lines.append(f"  - {it['kind']}：{it.get('path','')} — {it.get('desc','')}")
            hint = (
                f"备份未完成：{client_type} 的配置清单要求收齐以下条目，但 config 里缺少 "
                f"{missing}。\n请读取下列每一项的本地内容后重新调用 syncagent_backup（key 用条目的 kind）；"
                f"若某项在本机确实不存在，也要把该 key 显式设为 null 表示“已检查、不存在”，不要直接省略：\n"
                + "\n".join(missing_lines)
                + "\n注意：密钥类文件（API key / token）无需备份，恢复后本机重配即可。"
            )
            return {"content": [{"type": "text", "text": hint}], "isError": True}

        # 剥离 AI 有时自作主张塞进来的元数据键（非文件内容），不入库。
        config = {k: v for k, v in config.items() if k not in RESERVED_CONFIG_KEYS}

        synced_at = datetime.now().isoformat()
        _storage_put(_config_key(user_id, client_type), {
            "config": config,
            "synced_at": synced_at,
        })
        # 更新索引
        index = _storage_get(_config_index_key(user_id)) or {"clients": {}}
        index["clients"][client_type] = synced_at
        _storage_put(_config_index_key(user_id), index)
        # 报告实际备份了哪些项（区分有内容 / 本机不存在）
        present = [k for k in expected if config.get(k) not in (None, "", {}, [])]
        absent = [k for k in expected if k in config and config.get(k) in (None, "", {}, [])]
        line = f"✓ 已备份 {client_type} 配置到云端（{synced_at}）\n  已收录：{present or '无'}"
        if absent:
            line += f"\n  本机不存在（已记录为空）：{absent}"
        text = line

    elif tool_name == "syncagent_restore":
        from_client = arguments.get("from_client")
        index = _storage_get(_config_index_key(user_id)) or {"clients": {}}
        clients = index.get("clients", {})
        if not clients:
            text = "云端暂无配置，无法恢复。"
        elif from_client:
            entry = _storage_get(_config_key(user_id, from_client))
            if not entry:
                text = f"云端没有 {from_client} 的配置。"
            else:
                text = _build_restore_plan(from_client, entry.get("config", {}))
        else:
            # 未指定来源：默认恢复最近备份的那个客户端，避免把多个客户端的文件混写。
            latest = max(clients.items(), key=lambda kv: kv[1] or "")[0]
            entry = _storage_get(_config_key(user_id, latest))
            if not entry:
                text = f"云端没有 {latest} 的配置。"
            else:
                others = [c for c in clients if c != latest]
                text = _build_restore_plan(latest, entry.get("config", {}))
                if others:
                    text += f"\n\n（云端还有其它客户端备份：{others}。如需恢复其中某个，调用 syncagent_restore 时传 from_client。）"

    elif tool_name == "syncagent_status":
        index = _storage_get(_config_index_key(user_id)) or {"clients": {}}
        clients = index.get("clients", {})
        if not clients:
            text = "云端暂无配置"
        else:
            lines = ["云端配置："]
            for client_type, synced_at in clients.items():
                lines.append(f"- {client_type}（{synced_at}）")
            text = "\n".join(lines)

    elif tool_name == "syncagent_get_backup_manifest":
        client_type = arguments.get("client_type", "unknown")
        manifest = _get_manifest(client_type)
        payload = {
            "client_type": client_type,
            "display_name": manifest["display_name"],
            "items": manifest["items"],
            "instruction": (
                "请读取上面 items 里列出的每个本地文件/目录的实际内容，组装成一个 config 对象后调用 syncagent_backup。"
                "【格式】config 的键是条目的 kind；值必须是文件清单数组：[{\"relpath\": \"相对配置根目录的路径\", \"content\": \"文件内容\"}, ...]。"
                "目录类条目（skills / memory 等）把目录下每个文件各作为数组里的一个元素，relpath 用相对路径保留原始文件名与子目录结构（如 skills/git-helper/SKILL.md），这样恢复时才能还原到原位。单文件条目也用长度为 1 的数组。"
                "【必须收齐所有条目，禁止只备份一部分，禁止反过来询问用户是否要备份 skills/memory/soul——它们都是必备项。】"
                "若某个条目在本机确实不存在（如没有 SOUL.md），把对应 key 显式设为 null，表示“已检查、不存在”，不要省略该 key，否则备份会被判定为未完成并打回。"
                "【密钥例外】mcp / 配置类文件里的 API key、token 等密钥无需备份：请只保留配置结构，把密钥值替换为占位符或删除；恢复后由用户在新机器本地重新配置。"
            ),
        }
        text = json.dumps(payload, ensure_ascii=False)
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

# ============= "我的备份" 只读 API（JWT 鉴权）=============

@app.get("/api/backups")
async def list_backups(authorization: Optional[str] = Header(None)):
    """列出当前用户所有客户端的备份摘要。"""
    user_id = verify_token(authorization)
    index = _storage_get(_config_index_key(user_id)) or {"clients": {}}
    clients = index.get("clients", {})

    backups = []
    for client_type, synced_at in clients.items():
        manifest = _get_manifest(client_type)
        entry = _storage_get(_config_key(user_id, client_type))
        config = (entry or {}).get("config", {}) or {}
        item_keys = list(config.keys()) if isinstance(config, dict) else []
        backups.append({
            "client_type": client_type,
            "display_name": manifest["display_name"],
            "synced_at": synced_at,
            "item_count": len(item_keys),
            "items": item_keys,
        })

    # 最近备份排前面
    backups.sort(key=lambda b: b.get("synced_at") or "", reverse=True)
    return {"backups": backups}


@app.get("/api/backups/{client_type}")
async def get_backup_detail(client_type: str, authorization: Optional[str] = Header(None)):
    """查看某客户端备份的详细内容。"""
    user_id = verify_token(authorization)
    entry = _storage_get(_config_key(user_id, client_type))
    if not entry:
        raise HTTPException(status_code=404, detail="该客户端暂无备份")

    manifest = _get_manifest(client_type)
    return {
        "client_type": client_type,
        "display_name": manifest["display_name"],
        "synced_at": entry.get("synced_at"),
        "config": entry.get("config", {}),
    }


@app.delete("/api/backups/{client_type}")
async def delete_backup(client_type: str, authorization: Optional[str] = Header(None)):
    """删除某客户端的备份：移除配置对象，并从索引中摘除该 client。"""
    user_id = verify_token(authorization)

    index = _storage_get(_config_index_key(user_id)) or {"clients": {}}
    clients = index.get("clients", {})
    entry = _storage_get(_config_key(user_id, client_type))

    if not entry and client_type not in clients:
        raise HTTPException(status_code=404, detail="该客户端暂无备份")

    # 删除配置对象
    _storage_delete(_config_key(user_id, client_type))
    # 从索引摘除
    if client_type in clients:
        del clients[client_type]
        index["clients"] = clients
        _storage_put(_config_index_key(user_id), index)

    return {"deleted": client_type, "remaining": list(clients.keys())}


@app.get("/debug/storage")
async def debug_storage():
    """只读诊断：确认线上是否启用 R2。绝不返回任何密钥。"""
    return {
        "r2_enabled": _R2_ENABLED,
        "endpoint": R2_ENDPOINT,
        "bucket": R2_BUCKET,
        "backend": "r2" if _R2_ENABLED else "memory",
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
