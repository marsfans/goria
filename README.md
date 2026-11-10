# goria — 类 aria2 下载工具 (Go)

库: cobra + pflag (CLI) / viper (配置 + 环境变量) / lipgloss + termenv (多任务进度条) / pterm (日志、汇总表) / anacrolix/torrent (BT) / x/time/rate (限速)

功能: HTTP/HTTPS 多连接分段下载、断点续传 (.goria 控制文件)、并发任务、全局限速、代理、自定义 Header、失败重试、sha256/sha1/md5 校验、BT 种子与磁力链接、做种、会话持久化 (goria resume)、curl 兼容参数 (见下节)。

协议: HTTP/HTTPS (含 HTTP/2、HTTP/3)、FTP/FTPS、SFTP、BitTorrent/磁力链接。FTP/SFTP 同样支持分片下载与 .goria 断点续传、限速与校验:

- FTP: `goria ftp://user:pass@host/path/file` (凭据也可 `-u user:pass`, 缺省匿名; 被动模式, 每段一连接走 REST; `ftps://` 为显式 TLS; 服务器不支持 SIZE 时回落单连接; --proxy 不适用于 FTP)
- SFTP: `goria sftp://user@host/path/file` (密码/私钥/SSH agent 认证, `--sftp-private-key` 指定私钥, 缺省尝试 `~/.ssh/id_ed25519` 等与 agent; 有 known_hosts 时严格校验主机密钥; 代理仅支持 socks5)。两者均只下单文件, 不递归目录; `--range/--continue-at` 与 curl 请求参数不适用于 FTP/SFTP

```
goria -x 16 https://example.com/big.iso
goria -d ./dl -j 3 -i urls.txt
goria --max-speed 2M -o a.zip https://example.com/a.zip
goria --checksum sha256=... https://example.com/a.iso
goria "magnet:?xt=urn:btih:..."
goria ./ubuntu.torrent --seed-ratio 1.0
goria --save-session ./session.json -i urls.txt   # 保存未完成任务到会话文件
goria resume                                       # 恢复未完成任务
goria config            # 查看生效配置
```

## curl 兼容参数

常用 curl 参数名可以直接用 (含配置文件键与环境变量 `GORIA_*`)。与 aria2 命名冲突的短名保持原义、只提供长名: `-d` 仍是保存目录 (发送数据用 `--data`)、`-x` 仍是分片数 (代理用 `--proxy`)、`-m` 仍是重试次数 (超时用 `--max-time`)、`-i` 仍是任务列表 (响应头入文件用 `--include`)、`-k` 仍是最小分片 (`--insecure` 本就同名)。

第一档 (下载行为):

- 别名: `-A` = `--user-agent`、`--limit-rate` = `--max-speed`、`--proxy` = `--all-proxy`、`--output-dir` = `--dir`、`-Z/--parallel-max` = `-j`、`--retry` = `--max-tries`、`-O/-J` (goria 本就默认用远程/Content-Disposition 文件名)
- 请求头: `-e/--referer`、`-b/--cookie` (`a=b; c=d` 字面值, 或 Netscape 格式 cookie 文件)、`-c/--cookie-jar` 保存响应 Cookie、`-u/--user` Basic Auth
- TLS/网络: `--cacert`、`--cert/--key` (客户端证书)、`--compressed`、`-4/--ipv4`、`-6/--ipv6`
- 控制: `--connect-timeout`、`--max-time` (单任务总超时)、`--retry-delay`、`-L/--location` 与 `--no-location`、`--max-redirs`、`-f/--fail`、`-C/--continue-at` 按偏移续传、`-r/--range` 只下字节区间、`-z/--time-cond` 条件下载 (304 跳过)、`--create-dirs`

```
goria -A "Mozilla/5.0" -e https://ref.example/ -b "sid=42" https://example.com/a.zip
goria -r 0-1048575 https://example.com/big.iso        # 只下第一个 MiB
goria -z @last.zip https://example.com/last.zip       # 服务器未更新则跳过
goria -C 4096 https://example.com/big.iso             # 从已有文件的 4096 字节处续传
```

第二档 (单连接请求): 带请求体、非 GET 方法或 `--include` 的任务不分片、不写控制文件、不可断点续传, 其余 (限速、校验、cookie-jar、会话外) 照常。会话持久化不记录这类任务 (请求体可能含敏感数据)。

- `-X/--request` 方法; `--data` / `--data-binary` / `--data-raw` / `--data-urlencode` 发送数据 (`@文件` 语义与 curl 同, 多段以 `&` 连接, 有数据时默认 POST); `-F/--form` multipart (`name=value`、`name=@文件[;type=;filename=]`、`name=<文件`)
- `-I/--head` 只取响应头; `-D/--dump-header` 响应头写文件 (`-` 为 stderr); `--include` 响应头写入输出文件开头; `-v/--verbose` 打印请求/响应 (Authorization/Cookie 脱敏); `-s/--silent` 静默, `-S/--show-error` 静默时仍显示错误

协议选择 (仅 HTTPS; 明文 h2c 不支持):

- 默认自动协商: HTTPS 经 ALPN 协商 HTTP/2, 失败回落 HTTP/1.1
- `--http1.1` 强制 HTTP/1.1 (配置文件键为 `http11`; 与 `--http2/--http3` 冲突)
- `--http2` 要求协商出 HTTP/2, 谈不出就报错不下载
- `--http3` 先直连目标端口试 HTTP/3 (QUIC/UDP, 不做 Alt-Svc 发现), 传输失败回落 TCP 并锁定; `--http3-only` 只用 HTTP/3 不回落 (不能与代理同用)。TLS 参数 (`--cacert/--cert/--key/--insecure`) 对 QUIC 同样生效
- 状态码按 curl 语义: 默认保存响应体 (如 404 页面), 加 `-f/--fail` 后 >=400 报错且不落盘; 传输错误按 `--max-tries` 重试 (每次重发完整请求体)

```
goria -X POST --data "a=1" --data "b=2" -o resp.json https://api.example.com/submit
goria -F "name=goria" -F "file=@a.zip" https://example.com/upload
goria -I https://example.com/big.iso
goria --data-urlencode "q=a b&c" -o r.txt https://example.com/search
```
Ctrl+C 中断后重新运行相同命令即可续传; 开启会话持久化后可直接 `goria resume`。

## 会话持久化

- `--save-session PATH` (也可写入配置文件或环境变量 `GORIA_SAVE_SESSION`): 启动时、每 5 秒、退出/中断时保存未完成任务及其参数 (dir / -o / checksum / header), 默认关闭。进程被强杀最多丢失一个保存周期的状态。
- `goria resume`: 从 `~/.config/goria/session.json` (或 `--save-session` 指定的文件) 恢复未完成任务, 可在命令后追加新任务; 恢复后继续写回同一会话文件。
- 会话只记录任务列表, 字节级进度仍由 `.goria` 控制文件负责: 恢复后 HTTP 从断点续传, 已完成的文件自动跳过, BT 重新校验已有分块后继续下载。
- resume 的全局选项 (限速、并发数等) 以当前配置文件/环境变量为准; 每任务的目录与下载参数从会话恢复。BT 任务统一使用当前全局目录 (DataDir 是客户端级设置)。
