# 2026-07-22 漏洞修复报告

> **项目名称：** 用户管理系统（Class01）
> **报告日期：** 2026-07-22
> **修复人：** 王宇杨
> **远程仓库：** `github.com/1343313511/shixun`
> **分支：** `main`

---

## 一、修复概述

本次针对新版项目（`/项目/` 目录）中个人中心和充值功能存在的安全漏洞进行了全面修复，同时改进了已有修复的完整性。共涉及 **7 类漏洞/缺陷** 的修复。

| 编号 | 漏洞名称 | 风险等级 | 状态 |
|------|---------|---------|:----:|
| FIX-001 | 注册未设置余额字段（NULL 导致页面异常） | 🟠 中危 | ✅ 已修复 |
| FIX-002 | 注册缺少输入校验（用户名/密码长度） | 🟡 低危 | ✅ 已修复 |
| FIX-003 | Profile/Recharge 缺少 IDOR 防护 | 🔴 高危 | ✅ 已修复 |
| FIX-004 | Recharge 缺少 CSRF 保护 | 🔴 高危 | ✅ 已修复 |
| FIX-005 | 余额存储单位不统一（元/分混用） | 🟠 中危 | ✅ 已修复 |
| FIX-006 | 文件上传缺少魔数校验 | 🟠 中危 | ✅ 已修复 |
| FIX-007 | 搜索功能缺少 XSS 防护 | 🔴 高危 | ✅ 已修复 |
| ➕ | 数据库连接未使用上下文管理器（连接泄漏） | 🟡 低危 | ✅ 已优化 |
| ➕ | 同名文件上传互相覆盖 | 🟡 低危 | ✅ 已优化 |

---

## 二、漏洞详情与修复方案

### FIX-001：注册未设置余额字段

**问题：** 注册 SQL 的 `INSERT` 语句中没有包含 `balance` 字段，而新版的 `profile.html` 模板中需要显示余额。当浏览旧注册用户的 profile 时，`balance` 为 `NULL`，导致前端展示异常。

**漏洞代码（修复前）：**
```python
query = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
c.execute(query, (username, password_hash, email, phone))
```

**修复方案：** INSERT 语句加上 `balance` 字段，默认为 0。

```python
query = "INSERT INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, 0)"
```

同时修复 `get_user_info()` 对 `NULL` 余额的处理：
```python
"balance": row["balance"] if row["balance"] is not None else 0
```

---

### FIX-002：注册缺少输入校验

**问题：** 注册时仅检查了用户名和密码是否为空，没有用户名长度、密码强度的校验。

**修复方案：** 增加输入校验：
```python
elif len(username) < 2 or len(username) > 32:
    error = "用户名长度应为 2~32 个字符"
elif len(password) < 6:
    error = "密码长度不能少于 6 个字符"
```

---

### FIX-003：Profile / Recharge IDOR 漏洞

**严重级别：🔴 高危**

**问题：** `profile` 路由接受 `user_id` 参数但不校验当前用户有无权限访问其他用户的数据。攻击者可指定任意 `user_id` 查看其他用户的个人资料。

`recharge` 路由同样接受 `user_id` 作为表单参数，没有校验只能给自己充值。攻击者可以通过修改表单 `user_id` 给任意账户充值。

**示例攻击（修复前）：**
```
# 越权查看其他用户资料
GET /profile?user_id=2     ← 当前用户 ID=1，但可查看 ID=2 的资料

# 越权充值
POST /recharge  user_id=2&amount=99999  ← 当前用户 ID=1，给 ID=2 充值
```

**修复方案：** 增加 IDOR 防护，强制 `user_id` 必须等于当前登录用户 ID：
```python
# profile 路由
if user_id and str(user_id) != str(current_user["id"]):
    flash("无权查看其他用户的资料")
    return redirect(url_for("profile", user_id=current_user["id"]))

# recharge 路由
if user_id_int != current_user["id"]:
    flash("无权操作其他用户的账户")
    return redirect(url_for("profile"))
```

---

### FIX-004：Recharge 缺少 CSRF 保护

**严重级别：🔴 高危**

**问题：** `recharge` 路由是 POST 接口，但没有 CSRF token 校验。攻击者可构造恶意页面，诱导已登录用户访问，在用户不知情的情况下发起充值请求（跨站请求伪造）。

**修复方案：** 新增 CSRF 保护机制：

1. **生成 token** — 在 session 中存储 CSRF token，通过 `context_processor` 注入所有模板
2. **校验 token** — recharge 路由 POST 时校验 `_csrf_token`
3. **模板隐藏字段** — 在表单中加入 `{{ csrf_token }}`

```python
def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

def validate_csrf_token():
    token = request.form.get("_csrf_token", "")
    expected = session.pop("_csrf_token", None)
    if not expected or not secrets.compare_digest(expected, token):
        return False
    return True
```

---

### FIX-005：余额存储单位不统一

**问题：** 数据库中 `balance` 字段未明确定义单位。新功能设计为整数分存储（前端显示元），但旧数据以元存储时可能产生转换错误。

**修复方案：**
- 明确 `balance` 字段使用 `INTEGER DEFAULT 0`（整数分）
- `recharge` 路由中，接收的金额以元为单位，换算为分存储：
  ```python
  amount_fen = int(round(amount_yuan * 100))
  ```
- 前端展示时换算回元：`new_balance_yuan = new_balance_fen / 100.0`
- 防止余额溢出：
  ```python
  if new_balance_fen > 99999999999:
      flash("充值后余额超出上限")
  ```

---

### FIX-006：文件上传缺少魔数校验

**问题：** `upload` 路由只检查了文件名和后缀类型，没有检查文件内容（magic bytes）。攻击者可以上传伪装的恶意文件（如修改扩展名的 PHP shell），绕过后缀限制。

**修复方案：** 增加文件魔数（Magic Bytes）校验，允许的图片类型：
```python
is_image = False
if file_bytes[:8] == b"\x89PNG\r\n\x1a\n":      # PNG
    is_image = True
elif file_bytes[:2] in (b"\xff\xd8",):            # JPEG
    is_image = True
elif file_bytes[:3] == b"GIF":                    # GIF
    is_image = True
elif file_bytes[:4] == b"RIFF" and file_bytes[8:12] == b"WEBP":  # WebP
    is_image = True
```

---

### FIX-007：搜索功能 XSS 漏洞

**严重级别：🔴 高危**

**问题：** 搜索结果中的用户名、邮箱、手机号直接展示在页面上，如果搜索关键词中包含 `<script>` 标签或 HTML 特殊字符，会触发跨站脚本攻击（XSS）。

**示例攻击（修复前）：**
```
/search?keyword=<script>alert('XSS')</script>
```
搜索结果中显示包含恶意脚本的用户名，在用户浏览器中执行。

**修复方案：** 使用 `html.escape()` 对搜索结果中的用户数据进行 HTML 转义：
```python
import html as _html
for r in results:
    r["username"] = _html.escape(str(r["username"]))
    r["email"] = _html.escape(str(r.get("email", "")))
    r["phone"] = _html.escape(str(r.get("phone", "")))
```

同时对搜索关键词也做转义：
```python
safe_keyword = _html.escape(keyword) if keyword else keyword
```

---

### ➕ 附加优化

#### 数据库连接上下文管理器

将原有的手动 `conn = sqlite3.connect()` + `conn.close()` 模式重构为上下文管理器，异常时也能确保连接关闭：

```python
from contextlib import contextmanager

@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        conn.close()
```

所有数据库操作统一使用 `with get_db() as conn:` 包装。

#### 同名文件覆盖问题

不同的用户上传相同文件名的图片会互相覆盖。修复：使用用户名的 MD5 前缀区分文件名：

```python
user_prefix = hashlib.md5(username.encode()).hexdigest()[:8]
name_part, ext_part = os.path.splitext(safe_name)
unique_name = f"{user_prefix}_{name_part}{ext_part}"
```

---

## 三、修复文件清单

| 文件 | 变更类型 | 变更摘要 |
|------|---------|---------|
| `app.py` | 修改 | 7 类漏洞修复 + 代码重构 |
| `templates/base.html` | 修改 | 为 `recharge` 表单注入 CSRF token 等全局变量 |
| `templates/index.html` | 修改 | 修复余额显示单位（分→元） |
| `templates/profile.html` | 修改 | 修复余额显示单位 + CSRF token 支持 |
| `data/users.db` | 修改 | 数据库迁移（balance 字段改为整数分） |

---

## 四、修复验证

### 4.1 IDOR 防护验证

| 测试项 | 修复前 | 修复后 |
|-------|:-----:|:-----:|
| 查看自己的 profile | ✅ 正常 | ✅ 正常 |
| 查看别人的 profile（`user_id=2`） | ❌ 能看到 | ✅ 拒绝跳转 |
| 给自己充值 | ✅ 成功 | ✅ 成功 |
| 给别人充值（改表单 `user_id`） | ❌ 成功 | ✅ 拒绝 |

### 4.2 CSRF 防护验证

| 测试项 | 修复前 | 修复后 |
|-------|:-----:|:-----:|
| 正常表单提交 | ✅ 成功 | ✅ 成功 |
| 不带 `_csrf_token` 的 POST | ❌ 可执行 | ✅ 拒绝 |
| token 过期后重放 | ❌ 可执行 | ✅ 拒绝 |

### 4.3 XSS 防护验证

| 测试项 | 修复前 | 修复后 |
|-------|:-----:|:-----:|
| 搜索 `<script>alert(1)</script>` | ❌ 脚本执行 | ✅ 显示纯文本 |
| 搜索用户名含恶意 HTML | ❌ 脚本执行 | ✅ 显示纯文本 |

### 4.4 文件上传验证

| 测试项 | 修复前 | 修复后 |
|-------|:-----:|:-----:|
| 正常 PNG 上传 | ✅ 成功 | ✅ 成功 |
| 改扩展名的 PHP 文件（.php → .png） | ❌ 保存 | ✅ 魔数检测拒绝 |
| 不同用户上传同名文件 | ❌ 互相覆盖 | ✅ 独立存储 |

---

## 五、git 提交

```bash
git commit -m "fix: 全面修复IDOR/CSRF/XSS/余额单位/文件上传魔数校验等漏洞"
```

本次提交包含对 `app.py`、`base.html`、`index.html`、`profile.html` 和 `users.db` 的修改。

---

*报告由黄瓜（OpenClaw AI Agent）整理生成，2026-07-22*
