# goria — 类 aria2 下载工具 (Go)

库: cobra + pflag (CLI) / viper (配置 + 环境变量) / lipgloss + termenv (多任务进度条) / pterm (日志、汇总表) / anacrolix/torrent (BT) / x/time/rate (限速)

功能: HTTP/HTTPS 多连接分段下载、断点续传 (.goria 控制文件)、并发任务、全局限速、代理、自定义 Header、失败重试、sha256/sha1/md5 校验、BT 种子与磁力链接、做种、会话持久化 (goria resume)。

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
Ctrl+C 中断后重新运行相同命令即可续传; 开启会话持久化后可直接 `goria resume`。

## 会话持久化

- `--save-session PATH` (也可写入配置文件或环境变量 `GORIA_SAVE_SESSION`): 启动时、每 5 秒、退出/中断时保存未完成任务及其参数 (dir / -o / checksum / header), 默认关闭。进程被强杀最多丢失一个保存周期的状态。
- `goria resume`: 从 `~/.config/goria/session.json` (或 `--save-session` 指定的文件) 恢复未完成任务, 可在命令后追加新任务; 恢复后继续写回同一会话文件。
- 会话只记录任务列表, 字节级进度仍由 `.goria` 控制文件负责: 恢复后 HTTP 从断点续传, 已完成的文件自动跳过, BT 重新校验已有分块后继续下载。
- resume 的全局选项 (限速、并发数等) 以当前配置文件/环境变量为准; 每任务的目录与下载参数从会话恢复。BT 任务统一使用当前全局目录 (DataDir 是客户端级设置)。
