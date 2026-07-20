# SQL 注入漏洞分析报告

> 项目名称：用户管理系统（Class01）
> 报告日期：2026-07-20
> 修复状态：✅ 已修复

---

## 一、漏洞概述

在注册功能和搜索功能中，用户输入直接通过 f-string 拼接到 SQL 语句中，未做任何转义或过滤，导致存在 **SQL 注入漏洞**。攻击者可利用该漏洞执行任意 SQL 语句，获取或篡改数据库中的敏感数据。

| 漏洞编号 | 漏洞名称 | 风险等级 | 修复状态 |
|---------|---------|---------|---------|
| VULN-001 | 注册功能 SQL 注入 | 🔴 高危 | ✅ 已修复 |
| VULN-002 | 搜索功能 SQL 注入（含回显） | 🔴 高危 | ✅ 已修复 |
| VULN-003 | 密码明文存储 | 🟠 中危 | ✅ 已修复 |

---

## 二、漏洞详情

### VULN-001：注册功能 SQL 注入

**漏洞位置：** `/register` 路由（POST 方法）

**漏洞代码：**

```python
query = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
c.execute(query)
```

**攻击方式：** 攻击者在用户名、密码、邮箱或手机号中插入单引号 `'` 和 SQL 关键字，改变 SQL 语句结构。

**攻击示例 POC：**

```bash
# 构造单引号提前闭合 VALUES，绕过注册逻辑
curl -X POST http://127.0.0.1:5000/register \
  -d "username=hacker', 'pass', 'h@x.com', '123')--&password=ignored"
```

**生成的恶意 SQL：**

```sql
INSERT INTO users (username, password, email, phone) 
VALUES ('hacker', 'pass', 'h@x.com', '123')--', 'ignored', '', '')
```

`--` 注释掉后续 SQL，攻击者可以控制插入任意数据。

**危害：**
- 绕过密码验证，插入恶意账户
- 通过子查询获取其他表的数据
- 通过 `;` 执行多条 SQL 语句（取决于数据库驱动）

---

### VULN-002：搜索功能 SQL 注入（有回显）

**漏洞位置：** `/search` 路由

**漏洞代码：**

```python
search_sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
rows = c.execute(search_sql).fetchall()
```

**攻击方式：** 搜索关键词直接拼接到 SQL 的 LIKE 子句中，且搜索结果以表格形式返回给用户（有回显），攻击者可用 UNION 注入获取任意数据。

**攻击示例 1 — OR 万能条件：**

```bash
curl "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271"
# URL 解码: ' OR '1'='1
```

**生成的恶意 SQL：**

```sql
SELECT * FROM users 
WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
```

永真条件 `'1'='1'` 使条件始终成立，返回全部用户。

**攻击示例 2 — UNION 注入获取自定义数据：**

```bash
curl "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--"
# URL 解码: ' UNION SELECT 1,'inj','inj@x.com','138'--
```

**生成的恶意 SQL：**

```sql
SELECT * FROM users 
WHERE username LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%' 
      OR email LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'
```

`UNION SELECT` 将自定义行合并到搜索结果中，信息直接在页面展示。

**危害：**
- 未授权获取全部用户信息
- UNION 注入可读取任意表
- 有回显降低利用难度，可盲注也可显注

---

### VULN-003：密码明文存储

**漏洞位置：** `/register` 路由 INSERT 语句

**漏洞代码：** 注册时密码直接以明文存入数据库

```python
query = f"INSERT INTO users (...) VALUES ('{username}', '{password}', ...)"
```

**危害：**
- 数据库泄露后所有用户密码直接暴露
- 用户可能在其他平台使用相同密码，导致撞库攻击

---

## 三、修复方案

### 修复 1：参数化查询（Prepared Statement）

SQL 注入的根本原因是 **数据和代码未分离**。参数化查询将 SQL 语句结构和用户数据分开传输，数据库引擎自动处理数据中的特殊字符。

**注册路由修复后：**

```python
# ✅ 使用 ? 占位符，数据通过第二个参数传入
query = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
c.execute(query, (username, password_hash, email, phone))
```

**搜索路由修复后：**

```python
# ✅ LIKE 的值也通过参数传入，keyword 中的 % _ 等字符被转义为普通字符
search_sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
like_pattern = f"%{keyword}%"
c.execute(search_sql, (like_pattern, like_pattern))
```

**为什么参数化查询能防御 SQL 注入？**

```
用户输入: ' OR '1'='1
                  ↓  f-string 拼接
SQL 解释器看到: ... WHERE username LIKE '%' OR '1'='1%'
                ^^^^^^^^ 单引号闭合了 LIKE，'OR' 成为 SQL 关键字

用户输入: ' OR '1'='1
                  ↓  参数化查询
SQL 解释器看到: ... WHERE username LIKE ?   (参数: "%' OR '1'='1%")
                ^^^^^^^^ 单引号被视为普通字符，不做语法解析
                最终效果相当于: username LIKE "%' OR '1'='1%"
```

### 修复 2：密码哈希存储

```python
from werkzeug.security import generate_password_hash

# 注册时存储哈希
password_hash = generate_password_hash(password)
c.execute(query, (username, password_hash, email, phone))

# 登录时校验哈希
check_password_hash(stored_hash, input_password)
```

### 修复验证

修复后，使用之前的 POC 测试：

| 测试项 | 修复前 | 修复后 |
|-------|-------|-------|
| 正常搜索 `keyword=admin` | ✅ 返回 admin | ✅ 返回 admin |
| `' OR '1'='1` | ❌ 返回全部用户 | ✅ 返回空结果 |
| `' UNION SELECT 1,...` | ❌ 注入成功 | ✅ 返回空结果 |
| 注册注入 `hacker', ...)--` | ❌ 插入恶意数据 | ✅ 注册失败或正常注册 |

---

## 四、安全编码规范建议

### 4.1 永远不要拼接 SQL

```python
# ❌ 错误：f-string / 格式化 / + 拼接
query = f"SELECT * FROM users WHERE name = '{name}'"
query = "SELECT * FROM users WHERE name = '%s'" % name
query = "SELECT * FROM users WHERE name = '" + name + "'"

# ✅ 正确：参数化查询
query = "SELECT * FROM users WHERE name = ?"
c.execute(query, (name,))
```

### 4.2 使用 ORM 框架

使用 SQLAlchemy、Peewee 等 ORM 框架可以进一步减少手写 SQL 的机会。

### 4.3 输入验证

对特殊字符、预期格式做校验（作为辅助，不替代参数化查询）：
- 邮箱格式校验
- 手机号格式校验
- 用户名长度和字符集限制

### 4.4 最小权限原则

数据库连接使用只拥有必要权限的账号，禁止程序使用 root / DDL 权限。

### 4.5 敏感数据加密

- 密码：必须使用 bcrypt/scrypt/argon2 等自适应哈希算法
- 个人敏感信息（手机号、邮箱）：生产环境建议加密存储

---

## 五、总结

本次修复的安全问题均属于 **OWASP Top 10 2021: A03 Injection** 范畴。

| 修复项 | 变更文件 | 变更内容 |
|-------|---------|---------|
| 注册 SQL 注入 | `app.py` | 字符串拼接 → 参数化查询 |
| 搜索 SQL 注入 | `app.py` | 字符串拼接 → 参数化查询 |
| 密码明文存储 | `app.py` | 明文密码 → generate_password_hash |

修复方法最为彻底的解决方案是 **使用参数化查询或预编译语句**，确保 SQL 语句结构与用户输入永远隔离。
