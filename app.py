from flask import Flask, render_template, request, redirect, session, url_for

app = Flask(__name__)
app.secret_key = "dev-key-2025"  # TODO: 生产环境请改用环境变量
app.config["SESSION_PERMANENT"] = False

# TODO: 生产环境请使用数据库存储用户信息
USERS = {
    "admin": {
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": "alice2025",
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
        user.pop("password", None)  # 不暴露密码
        return user
    return None


@app.route("/")
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
        elif username in USERS and USERS[username]["password"] == password:
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
