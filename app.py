from flask import Flask, render_template, request, redirect, session, url_for, abort,\
    make_response, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
import time
import hashlib
import ipaddress
import io
import base64
import sqlite3
import os
import html as _html
import re as _re
import socket
import ssl
from contextlib import contextmanager
import urllib.request
import urllib.parse
import urllib.error

try:
    from PIL import Image, ImageDraw, ImageFont
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


app = Flask(__name__)
# ❗ 生产环境请使用固定密钥或环境变量，否则每次重启会话会失效
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_PERMANENT"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB

# ============================================================
# 防爆破配置
# ============================================================
login_attempts = {}

# 允许最大尝试次数（超过需验证码）
MAX_LOGIN_ATTEMPTS = 5
# 锁定时间（秒）
LOCKOUT_SECONDS = 300  # 5 分钟
# 基础延迟（秒），失败后指数回退
BASE_DELAY = 1.0
# 验证码长度
CAPTCHA_LENGTH = 4


def get_client_ip():
    """获取客户端真实 IP（兼容代理场景）"""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def get_attempt_key():
    """生成状态键：组合 IP 和用户名，跟踪同一账户爆破"""
    ip = get_client_ip()
    username = request.form.get("username", "").strip().lower()
    raw = f"{ip}:{username}"
    return hashlib.md5(raw.encode()).hexdigest()


def check_rate_limit():
    """
    防爆破检查：
    1. 如果尝试超过阈值，要求验证码
    2. 如果已锁定，返回剩余等待时间
    3. 否则计算并施加指数回退延迟
    返回: (blocked: bool, captcha_required: bool, wait_seconds: int, error_msg: str or None)
    """
    now = time.time()
    key = get_attempt_key()
    record = login_attempts.get(key, {"count": 0, "last_time": 0, "locked_until": 0})

    # 清理过期记录
    login_attempts[key] = record

    # --- 检查是否在锁定期 ---
    if record["locked_until"] > now:
        remaining = int(record["locked_until"] - now)
        return True, False, remaining, f"账户已临时锁定，请 {remaining} 秒后再试"

    # --- 判断是否需要验证码 ---
    captcha_required = record["count"] >= MAX_LOGIN_ATTEMPTS

    return False, captcha_required, 0, None


def apply_delay_on_failure():
    """
    登录失败时，增加尝试计数并施加减速时延。
    时延算法：min(BASE_DELAY * (2 ** (count - 1)), 30)
    每次失败最多等 30 秒。
    """
    now = time.time()
    key = get_attempt_key()
    record = login_attempts.get(key, {"count": 0, "last_time": 0, "locked_until": 0})

    record["count"] += 1
    record["last_time"] = now

    # 如果超过阈值 -> 锁定
    if record["count"] >= MAX_LOGIN_ATTEMPTS * 2:
        record["locked_until"] = now + LOCKOUT_SECONDS
        record["count"] = 0  # 重置计数
        login_attempts[key] = record
        return

    login_attempts[key] = record

    # 指数回退延迟
    delay = BASE_DELAY * (2 ** (record["count"] - 1))
    delay = min(delay, 30.0)  # 最多 30 秒
    time.sleep(delay)


def on_login_success():
    """登录成功后清除失败记录"""
    key = get_attempt_key()
    login_attempts.pop(key, None)


# ============================================================
# 验证码生成
# ============================================================

def generate_captcha_text():
    """生成随机验证码文本（排除易混淆字符）"""
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(chars) for _ in range(CAPTCHA_LENGTH))


def generate_captcha_image(text):
    """生成验证码图片，返回 base64 PNG"""
    if HAS_PIL:
        width = 120
        height = 40
        image = Image.new("RGB", (width, height), (240, 240, 240))
        draw = ImageDraw.Draw(image)

        # 干扰线
        for _ in range(3):
            x1 = secrets.randbelow(width)
            y1 = secrets.randbelow(height)
            x2 = secrets.randbelow(width)
            y2 = secrets.randbelow(height)
            draw.line([(x1, y1), (x2, y2)], fill=(180, 180, 180), width=2)

        # 画文字
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 22)
        except (OSError, IOError):
            font = ImageFont.load_default()

        x_offset = 10
        for ch in text:
            y_offset = secrets.randbelow(6)
            r = secrets.randbelow(80) + 40
            g = secrets.randbelow(80) + 40
            b = secrets.randbelow(80) + 40
            draw.text((x_offset, 6 + y_offset), ch, fill=(r, g, b), font=font)
            x_offset += 26

        # 干扰点
        for _ in range(40):
            x = secrets.randbelow(width)
            y = secrets.randbelow(height)
            draw.point((x, y), fill=(150, 150, 150))

        buf = io.BytesIO()
        image.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    else:
        return None


# ============================================================
# CSRF 保护
# ============================================================

def generate_csrf_token():
    """生成并存储 CSRF token 到 session"""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token():
    """校验 CSRF token，失败则抛出异常"""
    token = request.form.get("_csrf_token", "")
    expected = session.pop("_csrf_token", None)
    if not expected or not secrets.compare_digest(expected, token):
        return False
    return True


# ============================================================
# SSRF 防护
# ============================================================

# 禁止访问的内网 IP 范围（RFC 1918 及特殊地址）
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),       # 本地回环
    ipaddress.ip_network("10.0.0.0/8"),         # A 类私有
    ipaddress.ip_network("172.16.0.0/12"),      # B 类私有
    ipaddress.ip_network("192.168.0.0/16"),     # C 类私有
    ipaddress.ip_network("169.254.0.0/16"),     # 链路本地
    ipaddress.ip_network("0.0.0.0/8"),          # 零地址
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT
    ipaddress.ip_network("198.18.0.0/15"),      # 基准测试
    ipaddress.ip_network("::1/128"),             # IPv6 回环
    ipaddress.ip_network("fc00::/7"),            # IPv6 唯一本地
    ipaddress.ip_network("fe80::/10"),           # IPv6 链路本地
]

# 允许访问的域名白名单（可选，空列表表示允许所有公网域名，但禁止内网）
ALLOWED_DOMAINS = []  # 例：["api.example.com"] 表示只允许此域名

# 允许的 URL Scheme
ALLOWED_SCHEMES = ("http", "https")

# 最大返回内容大小（字节）
MAX_RESPONSE_SIZE = 2 * 1024 * 1024  # 2MB

# 请求超时（秒）
REQUEST_TIMEOUT = 10



def is_private_ip(ip):
    """
    检查 IP 是否为私有/内网地址。
    支持 IPv4 和 IPv6。
    """
    try:
        addr = ipaddress.ip_address(ip)
        for network in PRIVATE_IP_RANGES:
            if addr in network:
                return True
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True  # 解析失败视为危险


def resolve_and_validate(url):
    """
    SSRF 核心防护：
    1. 校验 URL scheme
    2. 解析域名得到 IP
    3. 校验是否为内网/私有 IP
    
    返回: (safe: bool, error_msg: str or None, resolved_ip: str or None)
    """
    parsed = urllib.parse.urlparse(url)

    # 1. Scheme 校验
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"不支持的协议: {parsed.scheme}，仅允许 HTTP/HTTPS", None

    hostname = parsed.hostname
    if not hostname:
        return False, "URL 中缺少主机名", None

    # 2. 域名白名单检查
    if ALLOWED_DOMAINS:
        if hostname not in ALLOWED_DOMAINS:
            return False, f"域名 {hostname} 不在白名单中", None

    try:
        # 3. DNS 解析：获取所有 IP 地址
        #    使用 socket.getaddrinfo() 获取 IPv4 和 IPv6 地址
        addrinfo = socket.getaddrinfo(hostname, None)
        resolved_ips = set()
        for info in addrinfo:
            ip = info[4][0]
            resolved_ips.add(ip)

        if not resolved_ips:
            return False, f"无法解析域名: {hostname}", None

        # 4. 校验每个解析到的 IP 是否在内网范围
        for ip in resolved_ips:
            if is_private_ip(ip):
                return False, f"拒绝访问内网地址: {ip}（解析自 {hostname}）", None

        resolved_ip = next(iter(resolved_ips))
        return True, None, resolved_ip

    except socket.gaierror:
        return False, f"DNS 解析失败: {hostname}", None
    except Exception as e:
        return False, f"地址校验异常: {str(e)}", None


def safe_fetch_url(url):
    """
    安全的 URL 请求函数，内置 SSRF 防护。
    1. SSRF 校验（内网/私有 IP 拦截）
    2. 内容大小限制
    3. 请求超时
    4. SSL 验证
    
    返回: (success: bool, content_or_error: str, content_type: str or None)
    """
    # SSRF 校验
    safe, error_msg, resolved_ip = resolve_and_validate(url)
    if not safe:
        return False, error_msg, None

    # 设置默认 User-Agent
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }

    try:
        req = urllib.request.Request(url, headers=headers)

        # 创建 SSL 上下文（验证证书）
        ssl_ctx = ssl.create_default_context()

        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=ssl_ctx) as response:
            content_type = response.headers.get("Content-Type", "application/octet-stream")

            # 限制读取大小防止内存溢出
            content = response.read(MAX_RESPONSE_SIZE)

            # 只允许文本内容
            content_type_lower = content_type.lower()
            if "text" not in content_type_lower and "json" not in content_type_lower \
               and "xml" not in content_type_lower and "html" not in content_type_lower \
               and "javascript" not in content_type_lower and content_type_lower != "application/octet-stream":
                return False, f"不支持的文件类型: {content_type}", None

            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                text = content.decode("utf-8", errors="replace")

            return True, text, content_type

    except urllib.error.HTTPError as e:
        return False, f"HTTP 请求失败: {e.code} {e.reason}", None
    except urllib.error.URLError as e:
        return False, f"URL 请求异常: {str(e.reason)}", None
    except ssl.SSLError as e:
        return False, f"SSL 证书验证失败: {str(e)}", None
    except socket.timeout:
        return False, "请求超时", None
    except Exception as e:
        return False, f"请求异常: {str(e)}", None


@app.context_processor
def inject_globals():
    """向所有模板注入全局变量"""
    ctx = {
        "HAS_CAPTCHA": True,
        "csrf_token": generate_csrf_token(),
    }
    username = session.get("username")
    if username:
        user = get_user_info(username)
        if user:
            ctx["current_user"] = user
    return ctx


# ============================================================
# 数据库工具
# ============================================================

DATABASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DATABASE_PATH = os.path.join(DATABASE_DIR, "users.db")


@contextmanager
def get_db():
    """数据库连接上下文管理器，确保连接正常关闭"""
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        conn.close()


# ============================================================
# 用户 & 权限
# ============================================================

USERS = {
    "admin": {
        "username": "admin",
        "password": "scrypt…4eb8",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": "scrypt…1836",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


def get_user_info(username):
    """返回不包含密码的用户信息"""
    if not username:
        return None
    with get_db() as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, username, email, phone, balance FROM users WHERE username = ?",
            (username,)
        )
        row = c.fetchone()
        if row:
            return {
                "id": row["id"],
                "username": row["username"],
                "email": row["email"],
                "phone": row["phone"],
                "role": "admin" if row["username"] == "admin" else "user",
                "balance": row["balance"] if row["balance"] is not None else 0
            }
        return None


def get_user_by_id(user_id):
    """通过 id 获取用户信息"""
    if not user_id:
        return None
    with get_db() as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, username, email, phone, balance FROM users WHERE id = ?",
            (user_id,)
        )
        row = c.fetchone()
        if row:
            return {
                "id": row["id"],
                "username": row["username"],
                "email": row["email"],
                "phone": row["phone"],
                "role": "admin" if row["username"] == "admin" else "user",
                "balance": row["balance"] if row["balance"] is not None else 0
            }
        return None


def login_required(roles=None):
    """
    登录验证 + 角色权限控制装饰器
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            username = session.get("username")
            if not username:
                return redirect(url_for("login"))
            if roles:
                user_info = get_user_info(username)
                if user_info and user_info.get("role", "user") not in roles:
                    abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def verify_login(username, password):
    """
    验证用户名密码，使用恒定时间比较防止时序攻击。
    """
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        if row:
            return check_password_hash(row[0], password)
    # 用户名不存在时，也对空哈希做一次 check 保持耗时恒定
    check_password_hash(
        "scrypt:32768:8:1$dummy$dummyhashaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        password
    )
    return False


# ============================================================
# 数据库初始化
# ============================================================

def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs(DATABASE_DIR, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            balance INTEGER DEFAULT 0
        )
    ''')
    default_users = [
        ("admin",  generate_password_hash("admin123"),  "admin@example.com",  "13800138000", 99999),
        ("alice",  generate_password_hash("alice2025"), "alice@example.com", "13900139001", 100),
    ]
    for u, p, e, ph, bal in default_users:
        c.execute(
            "INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
            (u, p, e, ph, bal)
        )
    conn.commit()
    conn.close()
    print("[DB] 数据库初始化完成")


# ============================================================
# 路由
# ============================================================

@app.route("/")
@login_required()
def index():
    username = session.get("username")
    user = get_user_info(username)
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    captcha_required = False
    captcha_img = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        captcha_input = request.form.get("captcha", "").strip().upper()

        # --- 防爆破检查 ---
        blocked, need_captcha, wait_sec, block_error = check_rate_limit()
        captcha_required = need_captcha

        if blocked:
            error = block_error
            return render_template(
                "login.html", error=error,
                captcha_required=captcha_required,
                captcha_img=captcha_img
            )

        # --- 输入校验 ---
        if not username or not password:
            error = "用户名和密码不能为空"
            apply_delay_on_failure()
            return render_template(
                "login.html", error=error,
                captcha_required=captcha_required,
                captcha_img=captcha_img
            )

        # --- 验证码校验 ---
        if captcha_required:
            expected = session.pop("captcha", "")
            if not captcha_input or captcha_input != expected:
                error = "验证码错误"
                apply_delay_on_failure()
                captcha_text = generate_captcha_text()
                session["captcha"] = captcha_text
                captcha_img = generate_captcha_image(captcha_text)
                return render_template(
                    "login.html", error=error,
                    captcha_required=True,
                    captcha_img=captcha_img
                )

        # --- 密码验证 ---
        if verify_login(username, password):
            on_login_success()
            session["username"] = username
            flash("登录成功")
            return redirect(url_for("index"))
        else:
            error = "用户名或密码错误"
            apply_delay_on_failure()

            _, captcha_required, _, _ = check_rate_limit()
            if captcha_required:
                captcha_text = generate_captcha_text()
                session["captcha"] = captcha_text
                captcha_img = generate_captcha_image(captcha_text)

    else:
        session.pop("captcha", None)

    return render_template(
        "login.html", error=error,
        captcha_required=captcha_required,
        captcha_img=captcha_img
    )


@app.route("/captcha-image")
def captcha_image():
    """生成并返回验证码图片（base64 内联）"""
    captcha_text = generate_captcha_text()
    session["captcha"] = captcha_text
    img_b64 = generate_captcha_image(captcha_text)

    if img_b64:
        html = f'<img src="data:image/png;base64,{img_b64}" alt="captcha">'
        return html
    else:
        return captcha_text


@app.route("/register", methods=["GET", "POST"])
def register():
    """用户注册"""
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        if not username or not password:
            error = "用户名和密码不能为空"
        elif len(username) < 2 or len(username) > 32:
            error = "用户名长度应为 2~32 个字符"
        elif len(password) < 6:
            error = "密码长度不能少于 6 个字符"
        else:
            password_hash = generate_password_hash(password)
            query = "INSERT INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, 0)"
            try:
                with get_db() as conn:
                    c = conn.cursor()
                    c.execute(query, (username, password_hash, email, phone))
                    conn.commit()
                flash("注册成功，请登录")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "用户名已存在"
            except Exception as e:
                error = f"注册失败: {e}"

    return render_template("register.html", error=error)


@app.route("/search")
@login_required()
def search():
    """用户搜索"""
    keyword = request.args.get("keyword", "").strip()
    results = []

    if keyword:
        with get_db() as conn:
            c = conn.cursor()
            search_sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
            like_pattern = f"%{keyword}%"
            print(f"[SQL] 搜索(参数化): {search_sql} 参数: ('{like_pattern}', '{like_pattern}')")
            try:
                rows = c.execute(search_sql, (like_pattern, like_pattern)).fetchall()
                results = [dict(row) for row in rows]
            except Exception as e:
                print(f"[SQL] 搜索错误: {e}")

        # HTML 转义防止 XSS
        for r in results:
            r["username"] = _html.escape(str(r["username"]))
            r["email"] = _html.escape(str(r.get("email", "")))
            if "phone" in r:
                r["phone"] = _html.escape(str(r.get("phone", "")))

    username = session.get("username")
    user = get_user_info(username)
    safe_keyword = _html.escape(keyword) if keyword else keyword
    return render_template("index.html", user=user, results=results, keyword=safe_keyword)


def safe_filename(filename):
    """
    对上传文件名做安全处理：
    1. 去除路径穿越 (os.sep, .., null bytes)
    2. 只保留安全的字符
    3. 如果最终结果为空返回默认名
    """
    filename = filename.replace("\x00", "")
    filename = os.path.basename(filename)
    if not filename or filename in (".", ".."):
        return "unnamed"
    return filename


@app.route("/upload", methods=["GET", "POST"])
@login_required()
def upload():
    """用户头像上传"""
    error = None
    success = None
    file_url = None

    if request.method == "POST":
        if "file" not in request.files:
            error = "没有选择文件"
        else:
            f = request.files["file"]
            if f.filename == "":
                error = "文件名为空"
            else:
                safe_name = safe_filename(f.filename)
                upload_dir = os.path.join(app.root_path, "static", "uploads")
                os.makedirs(upload_dir, exist_ok=True)

                # ✅ 修复：以用户 ID 前缀保存，防止不同用户同名文件覆盖
                username = session.get("username", "anon")
                user_prefix = hashlib.md5(username.encode()).hexdigest()[:8]
                name_part, ext_part = os.path.splitext(safe_name)
                unique_name = f"{user_prefix}_{name_part}{ext_part}"
                save_path = os.path.join(upload_dir, unique_name)

                # 检查文件大小（单文件不超过 1MB）
                f.seek(0, os.SEEK_END)
                file_size = f.tell()
                f.seek(0)
                if file_size > 1 * 1024 * 1024:
                    error = "文件大小不能超过 1MB"
                else:
                    # 通过文件魔数校验
                    f.seek(0)
                    file_bytes = f.read(12)
                    f.seek(0)
                    is_image = False
                    if file_bytes[:8] == b"\x89PNG\r\n\x1a\n":
                        is_image = True
                    elif file_bytes[:2] in (b"\xff\xd8",):
                        is_image = True
                    elif file_bytes[:3] == b"GIF":
                        is_image = True
                    elif file_bytes[:4] == b"RIFF" and file_bytes[8:12] == b"WEBP":
                        is_image = True

                    if not is_image:
                        error = "只允许上传图片文件（PNG/JPEG/GIF/WebP）"
                    else:
                        f.save(save_path)
                        file_url = url_for("static", filename=f"uploads/{unique_name}")
                        success = f"文件上传成功: {unique_name}"

    return render_template("upload.html", error=error, success=success, file_url=file_url)


@app.route("/profile")
@login_required()
def profile():
    """个人中心 - 只能查看自己的资料"""
    current_user = get_user_info(session.get("username"))
    if not current_user:
        return redirect(url_for("login"))

    user_id = request.args.get("user_id", "")

    # IDOR 防护：user_id 必须与当前登录用户一致
    if user_id and str(user_id) != str(current_user["id"]):
        flash("无权查看其他用户的资料")
        return redirect(url_for("profile", user_id=current_user["id"]))

    return render_template("profile.html", profile_user=current_user, user_id=user_id)


@app.route("/recharge", methods=["POST"])
@login_required()
def recharge():
    """充值 - 只能给自己充值，amount 必须为正数，余额用整数（分）存储"""
    # CSRF 校验
    if not validate_csrf_token():
        flash("安全令牌验证失败，请重试")
        return redirect(url_for("profile"))

    current_user = get_user_info(session.get("username"))
    if not current_user:
        flash("请先登录")
        return redirect(url_for("login"))

    user_id = request.form.get("user_id", "")
    amount_str = request.form.get("amount", "0")

    try:
        user_id_int = int(user_id)
    except (ValueError, TypeError):
        flash("参数错误")
        return redirect(url_for("profile"))

    # IDOR 防护：只能给自己充值
    if user_id_int != current_user["id"]:
        flash("无权操作其他用户的账户")
        return redirect(url_for("profile"))

    try:
        amount_yuan = float(amount_str)
    except (ValueError, TypeError):
        flash("金额格式错误")
        return redirect(url_for("profile"))

    if amount_yuan <= 0:
        flash("充值金额必须为正数")
        return redirect(url_for("profile"))

    # 防止过大金额导致溢出
    if amount_yuan > 9999999.99:
        flash("单次充值金额不能超过 9999999.99 元")
        return redirect(url_for("profile"))

    amount_fen = int(round(amount_yuan * 100))

    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT balance FROM users WHERE id = ?", (user_id_int,))
        row = c.fetchone()
        if row:
            current_balance_fen = row[0] if row[0] is not None else 0
            new_balance_fen = current_balance_fen + amount_fen

            # 防止余额溢出
            if new_balance_fen > 99999999999:
                flash("充值后余额超出上限")
                return redirect(url_for("profile"))

            c.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance_fen, user_id_int))
            conn.commit()
            new_balance_yuan = new_balance_fen / 100.0
            flash(f"充值成功！当前余额: {new_balance_yuan:.2f} 元")
        else:
            flash("用户不存在")

    return redirect(url_for("profile"))


@app.route("/page", methods=["GET"])
def dynamic_page():
    """
    动态页面加载 - 从 pages/ 目录加载页面内容
    对 name 参数做安全处理，防止路径穿越
    """
    name = request.args.get("name", "")
    
    if not name:
        page_content = "请指定页面名称，例如 /page?name=help"
    else:
        # 安全处理：仅提取文件名部分，去除路径分隔符和 .. 穿越
        safe_name = os.path.basename(name)
        if not safe_name:
            page_content = "页面不存在"
        else:
            pages_dir = os.path.join(app.root_path, "pages")
            page_path = os.path.normpath(os.path.join(pages_dir, safe_name))
            
            # 确保文件在 pages/ 目录内
            if not page_path.startswith(os.path.normpath(pages_dir) + os.sep):
                page_content = "页面不存在"
            elif os.path.isfile(page_path):
                with open(page_path, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                # 尝试加上 .html 后缀
                page_path_html = page_path + ".html"
                if os.path.isfile(page_path_html):
                    with open(page_path_html, "r", encoding="utf-8") as f:
                        page_content = f.read()
                else:
                    page_content = "页面不存在"
    
    username = session.get("username")
    user = get_user_info(username) if username else None
    return render_template("index.html", user=user, page_content=page_content)


@app.route("/fetch-url", methods=["GET", "POST"])
@login_required()
def fetch_url():
    """
    安全的 URL 抓取工具 - 内置 SSRF 防护。
    用户可输入 URL 获取其内容，但严格禁止访问内网地址。
    """
    error = None
    result = None
    target_url = None
    resolved_ip = None
    content_type = None

    if request.method == "POST":
        target_url = request.form.get("url", "").strip()

        if not target_url:
            error = "请输入 URL"
        else:
            # 1. 补充默认协议
            if not target_url.startswith(("http://", "https://")):
                target_url = "https://" + target_url

            # 2. URL 格式校验
            parsed = urllib.parse.urlparse(target_url)
            if not parsed.hostname:
                error = "URL 格式无效"
            else:
                # 3. SSRF 前置校验（含 DNS 解析和内网 IP 拦截）
                safe, err_msg, ip = resolve_and_validate(target_url)
                if not safe:
                    error = err_msg
                else:
                    resolved_ip = ip
                    # 4. 安全抓取
                    success, content, ctype = safe_fetch_url(target_url)
                    if success:
                        result = content
                        content_type = ctype
                    else:
                        error = content

    return render_template(
        "fetch_url.html",
        error=error,
        result=result,
        target_url=target_url,
        resolved_ip=resolved_ip,
        content_type=content_type
    )


@app.route("/change-password", methods=["POST"])
def change_password():
    """
    修改密码 - 不需要原密码，不需要 CSRF Token，不需要验证 session
    任何已登录用户都可以修改任何人的密码
    """
    username = request.form.get("username", "").strip()
    new_password = request.form.get("new_password", "")
    
    if not username or not new_password:
        flash("用户名和密码不能为空")
        return redirect(url_for("profile"))
    
    if len(new_password) < 6:
        flash("密码长度不能少于 6 个字符")
        return redirect(url_for("profile", user_id=request.args.get("user_id", "")))
    
    password_hash = generate_password_hash(new_password)
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (password_hash, username)
        )
        if c.rowcount > 0:
            conn.commit()
            flash(f"用户 {username} 密码修改成功！")
        else:
            flash(f"用户 {username} 不存在")
    
    # 重定向回 profile，尽可能带上 user_id 参数
    return redirect(url_for("profile", user_id=request.form.get("user_id", "")))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="0.0.0.0", port=5000)
