# Class01 项目 Bug 修复报告

**日期：** 2026-07-19  
**修复人：** 王宇杨  
**仓库：** https://github.com/1343313511/-.git

---

## 概述

本项目是一个基于 Flask 的简单用户管理系统，包含登录、首页展示和登出功能。  
代码审查发现 **4 个严重级别** 和 **2 个中等级别** 的 Bug / 安全问题，已全部修复。

---

## Bug 清单及修复详情

### 🚨 Bug 1：登录后未正确重定向

**严重级别：** 严重  
**涉及文件：** `app.py` – `login()` 路由

**问题描述：**  
登录 POST 成功后使用了 `render_template("index.html", user=user)` 直接渲染模板，而非 `redirect("/")`。这导致：
- 浏览器 URL 仍停留在 `/login`
- 刷新页面会触发浏览器"确认重新提交表单"弹窗
- session 状态和页面渲染可能存在不一致

**修复方案：**  
替换为 `redirect(url_for("index"))`，符合 HTTP 的 Post/Redirect/Get 模式。

```python
# 修复前
session["username"] = username
return render_template("index.html", user=user)

# 修复后
session["username"] = username
return redirect(url_for("index"))
```

---

### 🚨 Bug 2：首页泄露用户密码

**严重级别：** 严重  
**涉及文件：** `templates/index.html`

**问题描述：**  
首页模板中包含了 `{{ user['password'] }}` 字段，登录后页面会直接显示用户的明文密码。  
这是严重的信息泄露。

**修复方案：**
1. 从 `index.html` 模板中移除密码字段
2. 新增 `get_user_info()` 安全函数，返回用户数据时自动剔除 `password`

---

### 🚨 Bug 3：login.html 注释泄漏管理员默认凭证

**严重级别：** 严重  
**涉及文件：** `templates/login.html`

**问题描述：**  
文件第一行存在 HTML 注释暴露默认管理员账号密码。

**修复方案：**  
移除该行注释。

---

### ⚠️ Bug 4：密码和密钥硬编码为明文

**严重级别：** 中等  
**涉及文件：** `app.py`

**问题描述：**
- 所有用户密码以明文存储在 `USERS` 字典中
- `app.secret_key` 硬编码为固定值 `"dev-key-2025"`

**修复方案：**
1. **密码哈希存储** — 使用 `werkzeug.security.generate_password_hash()` 进行 scrypt 哈希存储
2. **恒定时间比较** — 新增 `verify_login()`，用户名不存在时也对空哈希做一次校验，防御时序攻击
3. **随机 secret_key** — 使用 `secrets.token_hex(32)` 自动生成密钥

---

### ⚠️ Bug 5：缺少输入校验

**严重级别：** 中等  
**涉及文件：** `app.py` – `login()` 路由

**问题描述：**  
未对空的用户名/密码做校验，直接查询字典。

**修复方案：**  
增加空值校验，返回明确错误提示。

---

### 🚨 Bug 6：垂直越权（Vertical Privilege Escalation）

**严重级别：** 严重  
**涉及文件：** `app.py` – 所有路由

**问题描述：**  
系统设计了 `admin` 和 `user` 两个角色，但没有任何权限校验。如果后续增加管理员专属接口，普通用户可直接越权访问。

**修复方案：**  
新增 `login_required()` 装饰器，支持角色白名单控制：

```python
@login_required()                    # 任意登录用户
@login_required(roles=["admin"])     # 仅管理员
@login_required(roles=["admin", "user"])  # 多人种角色
```

无权限时返回 403 Forbidden。

---

### 🚨 Bug 7：缺少防爆破机制

**严重级别：** 严重  
**涉及文件：** `app.py`、`templates/login.html`

**问题描述：**  
登录接口无任何限制，攻击者可无限次尝试用户名密码进行暴力破解。

**修复方案：**

| 阶段 | 触发条件 | 后果 |
|------|----------|------|
| 1-4 次失败 | 仅延迟 | 指数回退：1s → 2s → 4s → 8s（最多 30s） |
| 5-9 次失败 | 延迟 + 验证码 | 需正确输入 PIL 生成图片验证码（含干扰线 + 噪点） |
| ≥10 次失败 | 锁定 5 分钟 | 同一 IP+用户名组合无法登录 |

**核心代码：**

```python
def apply_delay_on_failure():
    """登录失败时指数回退延迟"""
    delay = BASE_DELAY * (2 ** (count - 1))
    delay = min(delay, 30.0)
    time.sleep(delay)

def check_rate_limit():
    """检查是否需要验证码或是否已锁定"""
    if record["locked_until"] > now:
        return True    # 已锁定
    captcha_required = record["count"] >= MAX_LOGIN_ATTEMPTS  # 5次后
    return False, captcha_required
```

- 验证码：使用 PIL 生成 4 位随机字符（排除易混淆字符如 0/O/1/I），含随机颜色、干扰线和噪点
- 成功后自动清除失败记录
- IP 追踪兼容 `X-Forwarded-For` 代理场景

---

### 🔸 其他改进

| 项目 | 说明 |
|------|------|
| 使用 `url_for()` | 替换硬编码路由路径，便于后续修改 |
| 增加 `.strip()` | 对用户名做首尾空白处理 |
| 代码注释 | 增加 `TODO` 标记，提示生产环境改进方向 |
| 安全函数封装 | `get_user_info()` 统一管理用户数据暴露范围 |
| 时序攻击防护 | `verify_login()` 即使用户名不存在也执行哈希计算 |
| 验证码 | 使用 PIL 生成含干扰线和随机噪点的图片验证码 |

---

## 修复后文件清单

| 文件 | 操作 |
|------|------|
| `app.py` | ✅ 修复（新增防爆破、验证码、权限装饰器） |
| `templates/index.html` | ✅ 修复（移除密码字段） |
| `templates/login.html` | ✅ 修复（移除注释 + 新增验证码 UI） |
| `templates/base.html` | 未改动 |
| `static/css/style.css` | 未改动 |

---

## 验证

修复后可以通过以下方式验证：

```bash
cd /opt/Class01/项目
pip install flask pillow
python app.py
# 浏览器访问 http://localhost:5000
```

- 登录 `admin / admin123` 后应正确跳转到首页，不显示密码
- 查看登录页源码，不应看到管理员凭证注释
- 连续 5 次错误登录后应弹出验证码
- 连续 10 次错误后应锁定显示剩余时间
- 提交空表单应有错误提示
- 未登录直接访问 `/` 应重定向到登录页

---

*报告由王宇杨整理生成*
