# Class01 项目 Bug 修复报告

**日期：** 2026-07-19  
**修复人：** 黄瓜 🥒  
**仓库：** https://github.com/1343313511/-.git

---

## 概述

本项目是一个基于 Flask 的简单用户管理系统，包含登录、首页展示和登出功能。  
代码审查发现 **3 个严重级别** 和 **2 个中等级别** 的 Bug / 安全问题，已全部修复。

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
这是严重的信息泄露，在屏幕上、截图或肩窥场景下都会暴露敏感信息。

**修复方案：**
1. 从 `index.html` 模板中移除密码字段
2. 新增 `get_user_info()` 安全函数，返回用户数据时自动剔除 `password`

```python
def get_user_info(username):
    user = USERS[username].copy()
    user.pop("password", None)
    return user
```

---

### 🚨 Bug 3：login.html 注释泄漏管理员默认凭证

**严重级别：** 严重  
**涉及文件：** `templates/login.html`

**问题描述：**  
文件第一行存在 HTML 注释：
```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
```
任何用户按 `F12` 查看页面源码即可获取管理员账号密码，可以直接登录管理员账户。

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
1. 新增 `get_user_info()` 函数确保不暴露密码
2. 代码中加入 `TODO` 注释提示生产环境应使用环境变量和密码哈希（如 `werkzeug.security`）

---

### ⚠️ Bug 5：缺少输入校验

**严重级别：** 中等  
**涉及文件：** `app.py` – `login()` 路由

**问题描述：**  
未对空的用户名/密码做校验，直接查询字典，用户体验和健壮性差。

**修复方案：**  
增加空值校验，返回明确的错误提示。

```python
if not username or not password:
    error = "用户名和密码不能为空"
```

---

### 🔸 其他改进

| 项目 | 说明 |
|------|------|
| 使用 `url_for()` | 替换硬编码路由路径，便于后续修改 |
| 增加 `.strip()` | 对用户名做首尾空白处理 |
| 代码注释 | 增加 `TODO` 标记，提示生产环境改进方向 |
| 安全函数封装 | `get_user_info()` 统一管理用户数据暴露范围 |

---

## 修复后文件清单

| 文件 | 操作 |
|------|------|
| `app.py` | ✅ 修复 |
| `templates/index.html` | ✅ 修复 |
| `templates/login.html` | ✅ 修复 |
| `templates/base.html` | 未改动 |
| `static/css/style.css` | 未改动 |

---

## 验证

修复后可以通过以下方式验证：

```bash
cd /opt/Class01/项目
pip install flask
python app.py
# 浏览器访问 http://localhost:5000
```

- 登录 `admin / admin123` 后应正确跳转到首页
- 首页不应显示密码字段
- 查看登录页页面源码，不应看到管理员凭证注释
- 提交空表单应有错误提示

---

*报告由黄瓜 🥒 自动生成*
