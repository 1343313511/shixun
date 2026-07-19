from flask import Flask, render_template, request, redirect, session, url_for, abort,\
    make_response
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
import time
import hashlib
import io
import base64

try:
    from PIL import Image, ImageDraw, ImageFont
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    import random as _random
    import string as _string


app = Flask(__name__)
# TODO: 生产环境请使用环境变量（os.environ.get("SECRET_KEY")）
app.secret_key = secrets.token_hex(32)
app.config["SESSION_PERMANENT"] = False

# ============================================================
# 防爆破配置
# ============================================================
# 内存中存储登录失败记录（生产环境请改用 Redis）
# login_attempts[client_ip] = {"count": int, "last_time": float}
login_attempts = {}

# 允许最大尝试次数（超过需验证码）
MAX_LOGIN_ATTEMPTS = 5
# 锁定时间（秒）：超过 MAX_LOGIN_ATTEMPTS 后需等待
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

    if captcha_required:
        # 需要验证码，但不阻断（验证码校验在 login 路由中处理）
        pass

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
        # 锁定时直接返回，不再等待
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
            # 随机上下偏移
            y_offset = secrets.randbelow(6)
            r, g, b = secrets.randbelow(80) + 40, secrets.randbelow(80) + 40, secrets.randbelow(80) + 40
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
        # 无 PIL 时返回纯文本验证码（不推荐，但兜底）
        return None


@app.context_processor
def inject_captcha():
    """向模板注入验证码图片"""
    return {
        "HAS_CAPTCHA": True,
    }


# ============================================================
# 用户 & 权限
# ============================================================

USERS = {
    "admin": {
        "username": "admin",
        "password": "scrypt:32768:8:1$yFeYAXJWMmoohX6i$3609ceeaf2f515e413ce3701c289c1e6cf7b46074995047edf296d050be2c4d33fc746e89c6c29a3d448d86282b1b685a56a59c434b38533ba168de9c9344eb8",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": "scrypt:32768:8:1$SrCh5oMHKUUagSls$3eb6fa466b401017ea33666d9b33e93922c5d589e5452355e0abc6f5d3577a01b42baa85874d678c89f2a8d164a2b27967992dea05e05a560a1b9c1c4e3c1836",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


def get_user_info(username):
    """返回不包含密码的用户信息"""
    if username and username in USERS:
        user = USERS[username].copy()
        user.pop("password", None)
        return user
    return None


def login_required(roles=None):
    """
    登录验证 + 角色权限控制装饰器
    使用方式：
        @login_required()               # 仅需登录
        @login_required(roles=["admin"]) # 仅管理员可访问
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            username = session.get("username")
            if not username:
                return redirect(url_for("login"))
            if roles and username in USERS:
                user_role = USERS[username].get("role", "user")
                if user_role not in roles:
                    abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def verify_login(username, password):
    """
    验证用户名密码，使用恒定时间比较防止时序攻击。
    无论用户名是否存在，都执行哈希验证以避免响应时间差异。
    """
    if username in USERS:
        return check_password_hash(USERS[username]["password"], password)
    # 用户名不存在时，也对空哈希做一次 check 保持耗时恒定
    check_password_hash(
        "scrypt:32768:8:1$dummy$dummyhashaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        password
    )
    return False


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
                # 生成新的验证码
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
            return redirect(url_for("index"))
        else:
            error = "用户名或密码错误"
            apply_delay_on_failure()

            # 失败后重新检查是否需要验证码
            _, captcha_required, _, _ = check_rate_limit()
            if captcha_required:
                captcha_text = generate_captcha_text()
                session["captcha"] = captcha_text
                captcha_img = generate_captcha_image(captcha_text)

    else:
        # GET 请求：清除验证码
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


@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("captcha", None)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
