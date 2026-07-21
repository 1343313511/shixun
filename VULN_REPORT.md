# 漏洞分析报告

> 项目名称：用户管理系统（Class01）
> 报告日期：2026-07-21
> 修复状态：✅ 已修复

---

## 一、漏洞总览

| 漏洞编号 | 漏洞名称 | 风险等级 | 修复状态 |
|---------|---------|---------|---------|
| VULN-001 | 注册功能 SQL 注入 | 🔴 高危 | ✅ 已修复 |
| VULN-002 | 搜索功能 SQL 注入（有回显） | 🔴 高危 | ✅ 已修复 |
| VULN-003 | 密码明文存储 | 🟠 中危 | ✅ 已修复 |
| VULN-004 | 文件上传路径穿越 | 🔴 高危 | ✅ 已修复 |
| VULN-005 | 文件上传无大小限制 | 🟡 低危 | ✅ 已修复 |

---

## 二、SQL 注入漏洞（VULN-001 ~ VULN-003）

### 漏洞位置

- **VULN-001**：`/register` 路由，`INSERT INTO users` 语句
- **VULN-002**：`/search` 路由，`SELECT ... LIKE` 语句  
- **VULN-003**：注册时密码直接以明文拼接进 SQL

### 漏洞代码（修复前）

```python
# 注册 - 字符串拼接 + 明文密码
query = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"

# 搜索 - 字符串拼接
query = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
```

### 攻击方式

**OR 注入：**
```bash
curl "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271"
```
生成：`WHERE username LIKE '%' OR '1'='1%' ...` → 永真条件，返回所有用户

**UNION 注入：**
```bash
curl "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--"
```
生成：`WHERE ... LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'` → 自定义数据注入结果集

### 修复方案

✅ 参数化查询（Prepared Statement），数据和 SQL 语句分离：

```python
# 注册
query = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
c.execute(query, (username, password_hash, email, phone))

# 搜索
query = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
c.execute(query, (f"%{keyword}%", f"%{keyword}%"))
```

✅ 密码使用 `generate_password_hash()` 哈希后存储。

---

## 三、文件上传漏洞（VULN-004 ~ VULN-005）

### VULN-004：路径穿越漏洞

**漏洞位置：** `/upload` 路由

**漏洞代码（修复前）：**

```python
save_path = os.path.join(upload_dir, f.filename)
f.save(save_path)
```

**危害：** 攻击者上传文件名包含 `../` 时可跳出 `static/uploads/` 目录，覆盖任意文件。

**攻击示例：**

```bash
# 路径穿越 - 覆盖 /etc/passwd 或系统关键文件
curl -X POST http://127.0.0.1:5000/upload \
  -F "file=@malicious.txt" \
  -H "Cookie: session=..." \
  --form-string "filename=../../../etc/passwd"
```

生成路径：`/opt/Class01/static/uploads/../../../etc/passwd` → 实际写入 `/etc/passwd`

### VULN-005：无文件大小限制

**漏洞位置：** `/upload` 路由

**漏洞代码（修复前）：** 无任何大小检查

**危害：** 攻击者上传超大文件耗尽服务器磁盘空间，造成拒绝服务（DoS）。

### 修复方案

✅ **文件名消毒，防止路径穿越：**

```python
def safe_filename(filename):
    filename = filename.replace("\x00", "")  # 移除 null bytes
    filename = os.path.basename(filename)    # 只取 basename
    if not filename or filename in (".", ".."):
        return "unnamed"
    return filename
```

✅ **添加文件大小限制：**

```python
f.seek(0, os.SEEK_END)
file_size = f.tell()
f.seek(0)
if file_size > 1 * 1024 * 1024:  # 1MB
    error = "文件大小不能超过 1MB"
else:
    f.save(save_path)
```

---

## 四、修复验证

### SQL 注入修复验证

| 测试项 | 修复前 | 修复后 |
|-------|-------|-------|
| 正常搜索 `keyword=admin` | ✅ 返回 admin | ✅ 返回 admin |
| `' OR '1'='1` | ❌ 泄露全部用户 | ✅ 返回空结果 |
| `' UNION SELECT 1,2,3,4--` | ❌ 注入成功 | ✅ 返回空结果 |
| 注册注入 `hacker', ...)--` | ❌ 插入恶意数据 | ✅ 被拒绝或安全注册 |

### 文件上传修复验证

| 测试项 | 修复前 | 修复后 |
|-------|-------|-------|
| 正常上传 png | ✅ 成功 | ✅ 成功 |
| 文件名 `../../../etc/passwd` | ❌ 路径穿越成功 | ✅ 只保存为 `passwd` |
| 上传超大文件（>1MB） | ❌ 占用磁盘 | ✅ 返回错误提示 |

---

## 五、安全编码规范建议

### 5.1 永远不要拼接 SQL

```python
# ❌ 错误
query = f"SELECT * FROM users WHERE name = '{name}'"

# ✅ 正确
query = "SELECT * FROM users WHERE name = ?"
c.execute(query, (name,))
```

### 5.2 文件上传安全

```python
# ❌ 错误 - 直接使用用户文件名
f.save(os.path.join(upload_dir, f.filename))

# ✅ 正确 - 过滤路径穿越 + 限制大小
safe_name = os.path.basename(f.filename)
f.save(os.path.join(upload_dir, safe_name))
```

### 5.3 密码安全

始终使用自适应哈希算法（bcrypt/scrypt/argon2），通过 `generate_password_hash` 生成密码哈希。

### 5.4 通用原则

- 参数化查询是防御 SQL 注入的最有效手段
- 永远不要信任用户输入（文件名、路径、表单数据）
- 对文件操作始终使用 `os.path.basename()` 过滤路径
- 始终限制上传文件大小

---

## 六、修复变更清单

| 文件 | 变更内容 |
|------|---------|
| `app.py` | 注册 SQL → 参数化查询 `?` 占位符 |
| `app.py` | 搜索 SQL → 参数化查询 `?` 占位符 |
| `app.py` | 注册密码 → `generate_password_hash()` 哈希存储 |
| `app.py` | 上传 → 新增 `safe_filename()` 防路径穿越 |
| `app.py` | 上传 → 新增文件大小限制（1MB） |
