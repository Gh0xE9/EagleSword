# EagleSword

面向**授权安全测试**的 Web 资产探测与漏洞扫描工具，单二进制运行，支持批量目标、动态页面渲染、指纹识别、SSRF / XSS 检测与结果落盘。

> ⚠️ 本项目仅用于你拥有或已获得书面授权的目标，禁止用于任何未授权的扫描、攻击或测试。

## 免责声明

- 使用本工具即表示你已确认对目标具备合法测试授权，并愿意承担由此产生的全部法律责任。
- 作者与贡献者不对任何误用、滥用、业务中断或数据损失负责。
- 工具会向目标发起大量请求，请合理设置并发（`-t`），并谨慎使用 `-spider` / `-r`，避免对目标造成影响。
- 任何 API Key、Webhook、Cookie、Authorization 头都属于敏感信息，请勿提交到版本库。

## 功能

| 模块 | 能力 |
| --- | --- |
| 目标输入 | 单个 URL（`-u`）或目标文件（`-f`，每行一个，自动补全 http / https） |
| 页面解析 | HTML / JS 解析、接口与参数提取、域名提取、敏感信息检测 |
| 动态渲染 | 基于 chromedp 的无头浏览器渲染，默认开启（`-render`） |
| 资产与爬虫 | 站点爬取（`-spider`）、目录递归扫描（`-r`）、指纹识别（`handler/scanner/fingerprints.json`） |
| 漏洞检测 | SSRF（端口 / 网段 / 文件读取 / OOB 带外 / POST & JSON 参数化）、XSS（参数化 payload）、CORS 检查 |
| 并发与代理 | 多目标并发（默认 5，上限 50）、HTTP / SOCKS5 代理、自定义 Header / Cookie |
| 结果输出 | 控制台彩色输出；SSRF / XSS 结果保存为 `ssrf_results_*.txt`、`xss_results_*.txt` |
| 空间引擎 | Quake / Hunter / FOFA / Shodan 配置位（需在 `config.yaml` 自行填写，可选） |
| 可选通知 | 在 `notify.feishu` 配置 webhook（可选） |

## 环境要求

- Go 1.24+（见 `go.mod`）
- Chrome / Chromium：`-render` 默认开启，依赖本机可执行的浏览器；无浏览器时用 `-render=false` 关闭

## 构建

```bash
git clone https://github.com/Gh0xE9/EagleSword
cd EagleSword
go mod download          # 国内可加 GOPROXY=https://goproxy.cn,direct
go build -o eaglesword .
```

其他方式：

```bash
make build          # 当前平台，输出到 bin/
make build-all      # Linux / macOS / Windows 多平台，输出到 dist/
bash build.sh       # 跨平台脚本，支持 all|linux|macos|windows|clean
build.bat           # Windows
```

`bin/`、`dist/`、`release/` 与扫描结果文件均已被 `.gitignore` 忽略。

## 配置

程序**只读取运行目录下的 `config.yaml`**（找不到时尝试上级目录）。仓库里的 `config.yaml` 是模板，所有密钥位均为空：

```yaml
eaglesword:
  timeout: 10
  cookie:
api_key:
  quake:
  hunter:
  shodan:
  fofa:
  fofa_email:
notify:
  feishu:
risk:
  api_response_length: 100
  api_title_length: 10
dictionary:
  path: dict.txt
  response_length: 100
  response_timeout: 10
```

| 配置段 | 说明 |
| --- | --- |
| `eaglesword` | 超时（秒）、默认 Cookie |
| `api_key` | Quake / Hunter / Shodan / FOFA 的 Key，FOFA 还需 `fofa_email`；留空即不启用 |
| `notify.feishu` | 可选通知 webhook，留空即不启用 |
| `risk` | 接口响应长度与标题长度阈值，用于结果判定 |
| `dictionary` | 字典文件路径与响应判定阈值 |

**防误提交**：`config.yaml` 是被 Git 跟踪的模板文件，填入真实凭据后请勿 `git add`。建议在本地执行：

```bash
git update-index --skip-worktree config.yaml   # 让 Git 忽略你对模板的本地修改
git update-index --no-skip-worktree config.yaml  # 需要恢复跟踪时
```

该标记只影响本地工作区，不会写入仓库，也不会推送给其他人。

## 用法

```bash
./eaglesword -h                        # 查看全部参数
./eaglesword -u https://example.com   # 单目标常规扫描
./eaglesword -f targets.txt -t 10     # 批量目标，10 并发
```

更多示例：

```bash
# SSRF：指定网段 / 端口，并启用 OOB 带外检测
./eaglesword -u https://example.com -s -sips 192.168.1.0/24 -sports 80,443,8080 -soob https://your-oob.example

# XSS：携带 POST 参数进行参数化扫描
./eaglesword -u https://example.com -x yes -xpost "name=test&email=test@example.com"

# 全量漏洞扫描 + 代理 + 自定义请求头
./eaglesword -f targets.txt -a yes -t 10 -proxy http://127.0.0.1:8080 \
  -header "Authorization: Bearer <token>,X-Forwarded-For: 127.0.0.1"
```

### 参数

| 参数 | 说明 | 默认 |
| --- | --- | --- |
| `-u` | 单个目标 URL（http / https） | - |
| `-f` | 目标文件路径，每行一个 | - |
| `-t` | 并发线程数，上限 50 | `5` |
| `-render` | 无头浏览器渲染动态页面 | `true` |
| `-cookie` | 自定义 Cookie | - |
| `-header` | 自定义请求头，逗号分隔 `Key: Value,Key2: Value2` | - |
| `-spider` | 深度爬取（请求量很大，谨慎开启） | `false` |
| `-r` | 递归扫描发现的目录 | `false` |
| `-proxy` | HTTP / SOCKS5 代理 | - |
| `-s` | 启用 SSRF 扫描 | `false` |
| `-smethod` | SSRF 请求方法 | `GET` |
| `-sthreads` | SSRF 并发数 | `10` |
| `-stimeout` | SSRF 请求超时（秒） | `10` |
| `-sports` | 自定义端口，如 `80,443,8080` 或 `1-1000` | - |
| `-sips` | 自定义 IP 或 CIDR 网段，逗号分隔 | - |
| `-soob` | 带外检测（OOB）服务地址 | - |
| `-spost` / `-sjson` | 参数化 SSRF 的 POST / JSON 数据 | - |
| `-x` | 启用 XSS 扫描（传 `yes`） | - |
| `-xthreads` | XSS 并发数 | `10` |
| `-xtimeout` | XSS 请求超时（秒） | `10` |
| `-xpost` / `-xjson` | 参数化 XSS 的 POST / JSON 数据 | - |
| `-a` | 启用全部漏洞扫描（传 `yes`，即 XSS + SSRF） | - |
| `-h` | 显示帮助 | - |

> 注意：`-x` 与 `-a` 是字符串参数，必须显式传入 `yes` 才会启用，不是布尔开关。
