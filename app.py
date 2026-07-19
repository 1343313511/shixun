from flask import Flask, render_template, request, redirect, session, url_for, abort
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets

app = Flask(__name__)
# TODO: 生产环境请使用环境变量（os.environ.get("SECRET_KEY")）
app.secret_key = secrets.token_hex(32)
app.config["SESSION_PERMANENT"] = False

# TODO: 生产环境请使用数据库存储用户信息
# 密码已使用 werkzeug.security 哈希存储
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
        @login_required()           # 仅需登录
        @login_required(roles=["admin"])  # 仅管理员可访问
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
                    abort(403)  # 无权限
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


@app.route("/")
@login_required()
def index():
    username = session.get("username")
    user = get_user_info(username)
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            error = "用户名和密码不能为空"
        elif verify_login(username, password):
            session["username"] = username
            return redirect(url_for("index"))
        else:
            error = "用户名或密码错误"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
