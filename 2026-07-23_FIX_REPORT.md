# 2026-07-23 漏洞修复报告：文件包含漏洞

## 漏洞概述

在上次迭代中，新增了动态页面加载功能（`/page` 路由），但故意引入了以下安全漏洞：

### 漏洞1：路径穿越文件包含

**位置：** `app.py` 中的 `dynamic_page()` 函数

**问题代码：**
```python
page_path = os.path.join("pages", name)
```

`name` 参数直接取自 URL 查询参数，未做任何校验直接拼接到文件路径中。

**攻击示例：**
```
/page?name=../app.py
/page?name=../../../etc/passwd
/page?name=../templates/base.html
```

由于 `os.path.join("pages", "../app.py")` 的结果是 `app.py`，攻击者可以通过 `../` 穿越到 `pages/` 目录之外，读取服务器上的任意文件（如 `app.py` 源码、`/etc/passwd` 等系统文件）。

### 漏洞2：HTML 渲染 XSS

**位置：** `templates/index.html`

**问题代码：**
```html
{{ page_content | safe }}
```

使用 Jinja2 的 `| safe` 过滤器会禁用 HTML 转义。如果攻击者能够控制 `page_content` 内容（例如通过读取包含用户输入的文件，或未来可能新增的写入功能），可直接注入 XSS。

### 漏洞3：相对路径问题

`os.path.join("pages", name)` 使用相对路径，工作目录取决于 Flask 的启动位置，存在不确定性。攻击者可能利用不同的工作目录扩大攻击面。

---

## 修复方案

### 修复1：路径穿越防护

在 `dynamic_page()` 中增加三重防护：

1. **`os.path.basename()` 过滤：** 只提取文件名部分，去除所有路径分隔符和 `..`
   ```python
   safe_name = os.path.basename(name)
   ```

2. **`os.path.normpath()` 与 `app.root_path` 组合：** 使用绝对路径规范化
   ```python
   pages_dir = os.path.join(app.root_path, "pages")
   page_path = os.path.normpath(os.path.join(pages_dir, safe_name))
   ```

3. **路径前缀校验：** 确保最终路径在 `pages/` 目录内
   ```python
   if not page_path.startswith(os.path.normpath(pages_dir) + os.sep):
       page_content = "页面不存在"
   ```

### 修复2：移除 `| safe` 过滤器

```diff
- {{ page_content | safe }}
+ {{ page_content }}
```

Jinja2 默认会对输出做 HTML 转义，防止 XSS。

### 修复3：使用绝对路径

通过 `app.root_path` 构建 `pages/` 目录的绝对路径，消除对工作目录的依赖。

---

## 修复后的代码

```python
@app.route("/page", methods=["GET"])
def dynamic_page():
    name = request.args.get("name", "")

    if not name:
        page_content = "请指定页面名称，例如 /page?name=help"
    else:
        safe_name = os.path.basename(name)
        if not safe_name:
            page_content = "页面不存在"
        else:
            pages_dir = os.path.join(app.root_path, "pages")
            page_path = os.path.normpath(os.path.join(pages_dir, safe_name))

            if not page_path.startswith(os.path.normpath(pages_dir) + os.sep):
                page_content = "页面不存在"
            elif os.path.isfile(page_path):
                with open(page_path, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                page_path_html = page_path + ".html"
                if os.path.isfile(page_path_html):
                    with open(page_path_html, "r", encoding="utf-8") as f:
                        page_content = f.read()
                else:
                    page_content = "页面不存在"

    username = session.get("username")
    user = get_user_info(username) if username else None
    return render_template("index.html", user=user, page_content=page_content)
```

## 验证

修复后以下攻击将被拦截：
| 攻击 URL | 结果 |
|---|---|
| `/page?name=../app.py` | 显示"页面不存在" |
| `/page?name=../../../etc/passwd` | 显示"页面不存在" |
| `/page?name=help` | 正常显示帮助页面 |
| `/page?name=../templates/base.html` | 显示"页面不存在" |

## 涉及文件

| 文件 | 变更 |
|---|---|
| `app.py` | 修复 `dynamic_page()` 路径穿越漏洞 |
| `templates/index.html` | 移除 `| safe` 过滤器，使用默认 HTML 转义 |
