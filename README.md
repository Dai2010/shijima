# shijima

本地 HTTPS 抓包代理。在本机开一个代理端口，把请求的**来源、目标、类型、内容**记录下来，
默认只监听回环地址，不对外提供任何服务。

| 项 | 取值 |
| --- | --- |
| 语言 | C++17（OpenSSL 负责 TLS） |
| 默认监听 | `127.0.0.1:8899`，被占用时自动顺延，也可用 `-p` 指定 |
| 介质 | MITM 解密 HTTPS；`--tunnel` 只做隧道 |
| 抓包文件 | 运行目录下 `shijima-capture.json` / `.jsonl` / `.xml` |
| 过滤规则 | 通配符，YAML 存于 `~/.config/shijima/rules.yaml` |
| 常驻内存 | 实测约 10 MB（空闲与 5 条连接后基本一致） |
| 交互 | 普通输出或 `--tui` 全屏仪表盘（按钮可鼠标点击） |

## 构建

```sh
# Termux
pkg install clang openssl
make -j1            # 单线程构建，避免抢占 CPU

# Debian / Ubuntu / Arch 等桌面发行版
sudo apt install build-essential libssl-dev   # 或 pacman -S base-devel openssl
make -j1
sudo make install PREFIX=/usr/local
```

要求 OpenSSL 1.1.1+（内存 BIO、TLS 1.3）。

## 快速开始

```sh
shijima -p 8899
```

首次运行会在 `~/.local/state/shijima/` 生成 CA（`ca.pem` 与 0600 的 `ca-key.pem`）。
启动输出会打印实际端口，以及：

```sh
export https_proxy=http://127.0.0.1:8899
export http_proxy=http://127.0.0.1:8899
```

或者单次：

```sh
curl -x http://127.0.0.1:8899 https://example.com/
```

### 让客户端信任 CA

不装 CA 也能跑，但 HTTPS 会因证书不受信而失败（隧道模式除外）。

- **Firefox**：设置 → 隐私与安全 → 证书 → 查看证书 → 证书颁发机构 → 导入 `ca.pem`，勾选“信任由此 CA 标识的网站”。
- **Chrome / Chromium（Linux）**：`certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n shijima -i ~/.local/state/shijima/ca.pem`（需 `libnss3-tools`）。
- **Debian / Ubuntu 系统信任库**：复制到 `/usr/local/share/ca-certificates/shijima.crt` 后执行 `sudo update-ca-certificates`。
- **Android**：设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书，选择 `ca.pem`。注意 Android 7+ 的应用默认不信任用户 CA，部分应用还做了证书固定，这种情况只能看到域名与流量大小（加 `--tunnel`）。
- 打印路径与 SHA-256 指纹：`shijima --print-ca`。

## 抓包文件

默认写当前工作目录，启动时若已存在则把旧文件改名为 `.1`（只保留一份）。

```sh
shijima -o ./cap.json              # JSON 数组（默认）
shijima -f jsonl -o ./cap.jsonl    # 每行一个对象，崩溃也不易损坏
shijima -f xml  -o ./cap.xml       # XML
shijima --no-file                  # 只打印到终端
```

记录字段：

| 字段 | 含义 |
| --- | --- |
| `kind` | `connection` / `request` / `response` / `blocked` / `tunnel` / `error` / `summary` |
| `src` | 客户端地址 `ip:port` |
| `host` / `port` | 目标主机与端口 |
| `proto` | `HTTP/1.1`、`TLSv1.3` 等 |
| `method` / `target` | 请求方法与路径 |
| `status` | 响应码 |
| `content_type` | 响应 Content-Type |
| `size` | 正文字节数 |
| `duration_ms` | 请求到响应的耗时 |
| `preview` | 正文预览（文本截断；二进制给十六进制） |

正文预览默认 2048 字节（`--body-limit` 可调，上限 64 KiB）；不缓存完整报文，下载大文件也不会涨内存。
`--max-file` 控制单文件大小，超出后轮转为 `.1`。

## 过滤规则

支持 `fnmatch` 通配符，对域名和 IP 都生效：

```sh
shijima --deny '*.doubleclick.net,*.ads.example' --allow '*.example.com'
shijima --rules ./extra-rules.yaml
shijima --rules-file ~/.config/shijima/rules.yaml
```

- `deny` 始终优先。
- 只要存在任意 `allow`，未匹配的主机默认拒绝。
- 规则持久化在 `~/.config/shijima/rules.yaml`（YAML，可手改）：

```yaml
# shijima 过滤规则（YAML）
deny:
  - "*.doubleclick.net"
allow:
  - "*.example.com"
```

命中的连接会被直接拒绝（HTTP 返回 403），记录为 `blocked`，不会连接上游。

## TUI

```sh
shijima --tui
```

全屏仪表盘：连接/请求计数、上行下行、热点主机、最近记录、规则列表、输入行。
支持鼠标（SGR 协议）：

- 点最近记录里的域名 → 填入输入行；
- 点 `[允许]` / `[拦截]` → 用输入行的通配符新增规则；
- 点规则行 → 删除该规则；
- 点 `[清空]` / `[退出]`。

键盘同样可用：输入通配符后回车默认拦截；`a 模式` 允许、`d 模式` 拦截、`c` 清空、`q` 退出、`Ctrl-C` 退出。
TUI 只是本地终端界面，不额外监听端口。

## 退出概要

`Ctrl-C` / `SIGTERM` 后打印：

```
──────── shijima 抓包概要 ────────
监听端口      8899
运行时长      2m 13s
连接          18（MITM 15 / 隧道 3 / 拦截 2 / 错误 0）
请求 / 响应   147 / 147
上行 / 下行   1.2 MiB / 48.3 MiB
抓包文件      ./shijima-capture.json（412 条，1.4 MiB）
CA 证书       ~/.local/state/shijima/ca.pem
──────────────────────────────────
```

概要同时以 `summary` 记录写入抓包文件。

## 低内存设计

- 每个连接一个线程（256 KiB 栈），`poll` + 非阻塞 socket；TLS 用 OpenSSL 内存 BIO 双向驱动，避免多线程共享 `SSL*`。
- 固定 16 KiB 中继缓冲；单方向待写数据上限 256 KiB，超过就停止读取对端（背压）。
- 不缓存完整报文：正文只保留 `--body-limit` 字节预览，其余计数后丢弃。
- `--max-conn` 限制并发（默认 48），超限直接回 503。
- 证书缓存上限 128 个主机，按 LRU 淘汰。
- 实测 Termux aarch64：空闲 10.2 MB，5 条连接后 10.1 MB。

## systemd 用户服务

```sh
mkdir -p ~/.config/systemd/user
cp contrib/shijima.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now shijima
journalctl --user -u shijima -f
```

## 已知限制

- 只解析 HTTP/1.1；对上游只协商 `http/1.1`，因此不会出现 HTTP/2 帧。
- HTTP/3（QUIC）不走代理，抓不到。
- 做了证书固定的 App 无法解密，只能用 `--tunnel` 看域名与字节数。
- WebSocket / `101 Switching Protocols` 之后按原始流转发，只记录连接与字节数。
- `CONNECT` 到非 TLS 端口会自动退回隧道模式。
- 明文 HTTP（非 CONNECT）只接受 `http://` 绝对地址。

## 安全

- 默认只监听 `127.0.0.1`；绑定其他地址必须显式 `--allow-remote`，此时请自行加防火墙。
- CA 私钥 `ca-key.pem` 权限 0600，**拿到它就等于能伪造任意站点证书**，不要拷到别处。
- 抓包文件包含请求头与正文预览，可能含 Cookie/Token，注意存放位置。

## 许可

MIT
