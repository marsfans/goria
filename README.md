# goria — 类 aria2 下载工具 (Go)

库: cobra + pflag (CLI) / viper (配置 + 环境变量) / lipgloss + termenv (多任务进度条) / pterm (日志、汇总表) / anacrolix/torrent (BT) / x/time/rate (限速)

功能: HTTP/HTTPS 多连接分段下载、断点续传 (.goria 控制文件)、并发任务、全局限速、代理、自定义 Header、失败重试、sha256/sha1/md5 校验、BT 种子与磁力链接、做种。

```
goria -x 16 https://example.com/big.iso
goria -d ./dl -j 3 -i urls.txt
goria --max-speed 2M -o a.zip https://example.com/a.zip
goria --checksum sha256=... https://example.com/a.iso
goria "magnet:?xt=urn:btih:..."
goria ./ubuntu.torrent --seed-ratio 1.0
goria config            # 查看生效配置
```
Ctrl+C 中断后重新运行相同命令即可续传。
