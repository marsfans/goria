// goria: 一个类 aria2 的命令行下载工具
// 技术栈: cobra (命令) + pflag (参数) + viper (配置/环境变量) + lipgloss/termenv (终端 UI)
// 功能: HTTP/HTTPS 多连接分段下载、断点续传、并发任务、限速、代理、校验、BT 种子与磁力链接
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/time/rate"
)

type Options struct {
	Dir         string   `mapstructure:"dir"`
	Out         string   `mapstructure:"out"`
	Split       int      `mapstructure:"split"`
	MaxJobs     int      `mapstructure:"max-concurrent-downloads"`
	MaxSpeed    string   `mapstructure:"max-speed"`
	Headers     []string `mapstructure:"header"`
	UserAgent   string   `mapstructure:"user-agent"`
	Retries     int      `mapstructure:"max-tries"`
	MinSplit    string   `mapstructure:"min-split-size"`
	InputFile   string   `mapstructure:"input-file"`
	SeedRatio   float64  `mapstructure:"seed-ratio"`
	BTListen    int      `mapstructure:"listen-port"`
	Checksum    string   `mapstructure:"checksum"`
	Insecure    bool     `mapstructure:"insecure"`
	Proxy       string   `mapstructure:"all-proxy"`
	Quiet       bool     `mapstructure:"quiet"`
	SaveSession string   `mapstructure:"save-session"`

	// curl 兼容参数 (见 curl.go); 与 aria2 命名冲突的只提供长名:
	// -d 已是 dir (curl 为 --data)、-x 已是 split (curl 为 proxy)、
	// -k 已是 min-split-size (curl 为 insecure)、-m 已是 max-tries (curl 为 max-time)、
	// -i 已是 input-file (curl 为 include), 这些短名保持原义不改。
	Referer        string   `mapstructure:"referer"`
	Cookie         string   `mapstructure:"cookie"`
	CookieJar      string   `mapstructure:"cookie-jar"`
	User           string   `mapstructure:"user"`
	CACert         string   `mapstructure:"cacert"`
	Cert           string   `mapstructure:"cert"`
	SFTPKey        string   `mapstructure:"sftp-private-key"`
	Key            string   `mapstructure:"key"`
	Compressed     bool     `mapstructure:"compressed"`
	IPv4           bool     `mapstructure:"ipv4"`
	IPv6           bool     `mapstructure:"ipv6"`
	HTTP11         bool     `mapstructure:"http11"` // 配置键 http11; 命令行 --http1.1 在 RunE 里手动并入 (viper 键含点号会误作嵌套)
	HTTP2          bool     `mapstructure:"http2"`
	HTTP3          bool     `mapstructure:"http3"`
	HTTP3Only      bool     `mapstructure:"http3-only"`
	ConnectTimeout float64  `mapstructure:"connect-timeout"` // 秒
	MaxTime        float64  `mapstructure:"max-time"`        // 秒, 单任务总超时
	RetryDelay     float64  `mapstructure:"retry-delay"`     // 秒, 0 = 指数退避
	MaxRedirs      int      `mapstructure:"max-redirs"`      // -1 = Go 默认 (10)
	NoLocation     bool     `mapstructure:"no-location"`
	Location       bool     `mapstructure:"location"`
	Fail           bool     `mapstructure:"fail"`
	ContinueAt     string   `mapstructure:"continue-at"`
	Range          string   `mapstructure:"range"`
	TimeCond       string   `mapstructure:"time-cond"`
	CreateDirs     bool     `mapstructure:"create-dirs"`
	RemoteName     bool     `mapstructure:"remote-name"`        // -O: goria 本就默认用远程文件名, 接受作兼容
	RemoteHeadName bool     `mapstructure:"remote-header-name"` // -J: 同上, 默认已用 Content-Disposition
	Head           bool     `mapstructure:"head"`
	DumpHeader     string   `mapstructure:"dump-header"`
	Include        bool     `mapstructure:"include"`
	Verbose        bool     `mapstructure:"verbose"`
	Silent         bool     `mapstructure:"silent"`
	ShowError      bool     `mapstructure:"show-error"`
	Method         string   `mapstructure:"request"`
	Data           []string `mapstructure:"data"`
	DataBinary     []string `mapstructure:"data-binary"`
	DataRaw        []string `mapstructure:"data-raw"`
	DataURLEncode  []string `mapstructure:"data-urlencode"`
	Form           []string `mapstructure:"form"`

	limiter   *rate.Limiter
	minSplitB int64
	rangeBase int64    // --range 解析后的起始偏移 (文件内写入偏移基准), 0 表示普通下载
	rangeEnd  int64    // --range 解析后的结束偏移 (含), -1 表示未用 --range
	mirrors   []string // 同一文件的镜像 URL (Metalink 注入): probe 逐个试, 分段按段轮换并故障转移
}

// retryDelay 第 try 次重试前的等待时长 (try 从 0 计)
func (o *Options) retryDelay(try int) time.Duration {
	if o.RetryDelay > 0 {
		return time.Duration(o.RetryDelay * float64(time.Second))
	}
	return time.Duration(try+1) * time.Second
}

// mergeHTTP11Flag 并入 --http1.1: 该键名含点号, viper 会把点号当嵌套分隔符,
// 故不走 Unmarshal, 直接从命令行 flag 读 (配置文件请用 http11 键)
func mergeHTTP11Flag(opt *Options, cmd *cobra.Command) {
	if cmd.Flags().Lookup("http1.1") == nil {
		return // 子命令没有这个 flag (如 resume), 仅配置文件 http11 键生效
	}
	if v, err := cmd.Flags().GetBool("http1.1"); err == nil && v {
		opt.HTTP11 = true
	}
}

// applyCurlAliases 把 curl 别名参数的值并入主参数 (别名以独立 viper 键注册,
// 来源同样可以是命令行/环境变量/配置文件, 非空/非零时覆盖主参数)
func applyCurlAliases(opt *Options) {
	if v := viper.GetString("limit-rate"); v != "" {
		opt.MaxSpeed = v
	}
	if v := viper.GetString("proxy"); v != "" {
		opt.Proxy = v
	}
	if v := viper.GetString("output-dir"); v != "" {
		opt.Dir = v
	}
	if v := viper.GetInt("parallel-max"); v != 0 {
		opt.MaxJobs = v
	}
	if v := viper.GetString("agent"); v != "" {
		opt.UserAgent = v
	}
	if viper.IsSet("retry") {
		if v := viper.GetInt("retry"); v >= 0 {
			opt.Retries = v
		}
	}
}

var cfgFile string

func main() {
	root := &cobra.Command{
		Use:   "goria [flags] URL|MAGNET|TORRENT ...",
		Short: "类 aria2 的多协议下载工具 (HTTP/HTTPS/BitTorrent/Magnet)",
		Example: `  goria -x 16 https://example.com/big.iso
  goria -d ./dl -j 3 -i urls.txt
  goria --max-speed 2M -o a.zip https://example.com/a.zip
  goria "magnet:?xt=urn:btih:..."
  goria --save-session ./session.json -i urls.txt
  goria resume
  GORIA_ALL_PROXY=socks5://127.0.0.1:1080 goria https://...`,
		SilenceUsage: true,
		Args:         cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opt := &Options{}
			if err := viper.Unmarshal(opt); err != nil {
				return err
			}
			if !cmd.Flags().Changed("out") {
				opt.Out = "" // -o 不从配置文件继承
			}
			applyCurlAliases(opt)
			mergeHTTP11Flag(opt, cmd)
			return run(opt, args)
		},
	}

	f := root.Flags()
	root.PersistentFlags().StringVar(&cfgFile, "conf", "", "配置文件 (默认 ./goria.yaml 或 ~/.config/goria/goria.yaml)")
	f.StringP("dir", "d", ".", "保存目录")
	f.StringP("out", "o", "", "输出文件名 (仅单个任务)")
	f.IntP("split", "x", 8, "每个任务的最大连接数")
	f.IntP("max-concurrent-downloads", "j", 5, "同时进行的任务数")
	f.String("max-speed", "", "全局限速, 如 500K, 2M")
	f.StringArrayP("header", "H", nil, "附加 HTTP 头, 可重复: -H 'Cookie: a=b'")
	f.StringP("user-agent", "U", "goria/1.0", "User-Agent")
	f.IntP("max-tries", "m", 5, "每个分片的最大重试次数")
	f.StringP("min-split-size", "k", "1M", "最小分片大小")
	f.StringP("input-file", "i", "", "从文件读取任务 (每行一个, # 为注释)")
	f.Float64("seed-ratio", 0, "BT 完成后做种到该分享率 (0 不做种)")
	f.Int("listen-port", 0, "BT 监听端口 (0 随机)")
	f.String("checksum", "", "完成后校验, 如 sha256=abcd...")
	f.Bool("insecure", false, "跳过 TLS 证书校验")
	f.String("all-proxy", "", "代理: http://host:port 或 socks5://host:port")
	f.BoolP("quiet", "q", false, "不显示进度条, 只输出日志")
	root.PersistentFlags().String("save-session", "", "会话文件: 保存未完成任务, 供 goria resume 恢复 (空 关闭)")

	// ---- curl 兼容参数 (语义见 curl.go; 与 aria2 冲突的短名保持原义) ----
	f.StringP("referer", "e", "", "Referer 头")
	f.StringP("cookie", "b", "", "Cookie: 'a=b; c=d', 或 Netscape 格式 cookie 文件路径")
	f.StringP("cookie-jar", "c", "", "把响应 Cookie 保存到该文件 (Netscape 格式)")
	f.StringP("user", "u", "", "Basic Auth: user:password")
	f.String("cacert", "", "校验服务器用的 CA 证书文件 (PEM)")
	f.String("cert", "", "客户端证书文件 (PEM, 须与 --key 成对)")
	f.String("sftp-private-key", "", "SFTP 登录私钥文件 (缺省尝试 ~/.ssh/id_ed25519、id_rsa、id_ecdsa 与 SSH agent)")
	f.String("key", "", "客户端证书私钥文件 (PEM, 须与 --cert 成对)")
	f.Bool("compressed", false, "请求压缩传输并自动解压 (单连接路径)")
	f.BoolP("ipv4", "4", false, "仅使用 IPv4")
	f.BoolP("ipv6", "6", false, "仅使用 IPv6")
	f.Bool("http1.1", false, "强制 HTTP/1.1 (禁用 HTTP/2 协商; 配置文件键为 http11)")
	f.Bool("http2", false, "要求 HTTPS 协商出 HTTP/2, 否则失败 (明文 http 不适用)")
	f.Bool("http3", false, "先尝试 HTTP/3 (QUIC), 失败回落到 TCP 传输 (仅 HTTPS)")
	f.Bool("http3-only", false, "只用 HTTP/3, 不回落 (仅 HTTPS, 不能与代理同用)")
	f.Float64("connect-timeout", 0, "连接超时 (秒, 支持小数)")
	f.Float64("max-time", 0, "单任务总超时 (秒, 支持小数; curl 的 -m, 本工具短名已被重试次数占用)")
	f.Float64("retry-delay", 0, "重试间隔 (秒, 0 = 指数退避)")
	f.Int("max-redirs", -1, "最大重定向次数 (-1 = 默认 10)")
	f.BoolP("location", "L", false, "跟随重定向 (本就默认跟随, 接受作兼容)")
	f.Bool("no-location", false, "不跟随重定向 (3xx 视为结果/错误)")
	f.BoolP("fail", "f", false, "HTTP 状态 >=400 时失败且不保存响应体 (单连接请求路径; 普通下载本就对错误状态失败)")
	f.StringP("continue-at", "C", "", "从指定偏移续传: - 表示自动 (默认行为), 或字节数如 4096")
	f.StringP("range", "r", "", "只下载指定字节区间, 如 0-499 / 500- / -500")
	f.StringP("time-cond", "z", "", "条件下载 (If-Modified-Since): 日期, 或 @文件/文件路径取其修改时间; 服务器未修改 (304) 时跳过")
	f.Bool("create-dirs", false, "-o 含子路径时自动创建目录")
	f.BoolP("remote-name", "O", false, "使用远程文件名 (本就默认, 接受作兼容)")
	f.BoolP("remote-header-name", "J", false, "使用 Content-Disposition 文件名 (本就默认, 接受作兼容)")
	f.BoolP("head", "I", false, "只发 HEAD 请求并输出响应头, 不下载")
	f.StringP("dump-header", "D", "", "把响应头写到该文件 ('-' 写到 stderr)")
	f.Bool("include", false, "把响应头也写入输出文件 (单连接请求路径; -i 短名已被任务列表占用)")
	f.BoolP("verbose", "v", false, "输出请求/响应行与头 (Authorization/Cookie 脱敏)")
	f.BoolP("silent", "s", false, "静默: 不显示进度与普通日志")
	f.BoolP("show-error", "S", false, "与 -s 同用时仍显示错误")
	f.StringP("request", "X", "", "HTTP 方法, 如 POST/PUT/DELETE (有 --data/--form 时默认 POST)")
	f.StringArray("data", nil, "发送表单数据 (等价 curl --data): 可重复, @文件 读文件并去换行; 多段以 & 连接")
	f.StringArray("data-binary", nil, "同 --data 但 @文件 按原样发送")
	f.StringArray("data-raw", nil, "同 --data 但 @ 不特殊处理")
	f.StringArray("data-urlencode", nil, "同 --data 但每段先做 URL 编码: content / name=content / @文件 / name@文件")
	f.StringArrayP("form", "F", nil, "multipart 表单: name=value / name=@文件[;type=类型;filename=名] / name=<文件")
	// 纯别名 (并入主参数, 见 applyCurlAliases)
	f.String("limit-rate", "", "--max-speed 的 curl 别名")
	f.String("proxy", "", "--all-proxy 的 curl 别名 (curl 的 -x 短名已被分片数占用)")
	f.String("output-dir", "", "--dir 的 curl 别名")
	f.Int("parallel-max", 0, "--max-concurrent-downloads 的 curl 别名")
	f.BoolP("parallel", "Z", false, "并行下载 (本就默认并行, 接受作兼容)")
	f.StringP("agent", "A", "", "--user-agent 的 curl 别名")
	f.Int("retry", -1, "--max-tries 的 curl 别名")

	root.AddCommand(&cobra.Command{
		Use:   "config",
		Short: "打印当前生效的配置",
		RunE: func(cmd *cobra.Command, _ []string) error {
			src := viper.ConfigFileUsed()
			if src == "" {
				src = "(未找到配置文件, 使用默认值/环境变量)"
			}
			pterm.DefaultSection.Println("当前配置 " + src)
			data := pterm.TableData{{"键", "值", "环境变量"}}
			for _, k := range viper.AllKeys() {
				env := "GORIA_" + strings.ToUpper(strings.ReplaceAll(k, "-", "_"))
				data = append(data, []string{k, fmt.Sprint(viper.Get(k)), env})
			}
			return pterm.DefaultTable.WithHasHeader().WithData(data).Render()
		},
	})
	root.AddCommand(&cobra.Command{
		Use:   "resume [URL|MAGNET|TORRENT ...]",
		Short: "恢复会话文件中未完成的任务, 可追加新任务",
		Example: `  goria resume
  goria resume --save-session ./session.json
  goria resume https://example.com/extra.zip`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opt := &Options{}
			if err := viper.Unmarshal(opt); err != nil {
				return err
			}
			if !cmd.Flags().Changed("out") {
				opt.Out = "" // -o 不从配置文件继承
			}
			applyCurlAliases(opt)
			mergeHTTP11Flag(opt, cmd)
			path := opt.SaveSession
			if path == "" {
				path = defaultSessionPath()
			}
			s, err := loadSession(path)
			if err != nil {
				if os.IsNotExist(err) {
					pterm.Info.Printfln("未找到会话文件 %s, 没有可恢复的任务", path)
					return nil
				}
				return fmt.Errorf("读取会话 %s 失败: %w", path, err)
			}
			jobs := buildResumeJobs(s, opt, args)
			if len(jobs) == 0 {
				pterm.Info.Println("没有待恢复的任务")
				return nil
			}
			opt.SaveSession = path // 恢复后继续写回同一会话
			pterm.Info.Printfln("从 %s 恢复 %d 个任务", path, len(jobs))
			return runJobs(opt, jobs)
		},
	})
	// 让子命令也能读取根命令的 flag 默认值
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		if err := initConfig(root.Flags()); err != nil {
			return err
		}
		// 子命令执行时, 持久化 flag 只合并在 cmd.Flags() 里
		return viper.BindPFlags(cmd.Flags())
	}

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// viper: flag > 环境变量 GORIA_* > 配置文件 > 默认值
func initConfig(fs *pflag.FlagSet) error {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("goria")
		viper.AddConfigPath(".")
		if home, err := os.UserHomeDir(); err == nil {
			viper.AddConfigPath(filepath.Join(home, ".config", "goria"))
		}
	}
	viper.SetEnvPrefix("GORIA")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	if err := viper.BindPFlags(fs); err != nil {
		return err
	}
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok && cfgFile != "" {
			return err
		}
	}
	return nil
}

type job struct {
	src string
	opt *Options // 每任务选项, 普通下载时共享全局 opt
}

func run(opt *Options, args []string) error {
	if opt.InputFile != "" {
		lines, err := readLines(opt.InputFile)
		if err != nil {
			return err
		}
		args = append(args, lines...)
	}
	if len(args) == 0 {
		return fmt.Errorf("请提供至少一个 URL / 磁力链接 / .torrent 文件")
	}
	if opt.Out != "" && len(args) > 1 {
		return fmt.Errorf("-o 只能用于单个任务")
	}
	jobs := make([]job, 0, len(args))
	for _, a := range args {
		jobs = append(jobs, job{src: a, opt: opt})
	}
	return runJobs(opt, jobs)
}

func runJobs(opt *Options, jobs []job) error {
	if err := validateOptions(opt); err != nil {
		return err
	}
	if opt.MaxJobs < 1 {
		opt.MaxJobs = 1
	}
	if err := os.MkdirAll(opt.Dir, 0o755); err != nil {
		return err
	}
	for _, j := range jobs {
		if err := os.MkdirAll(j.opt.Dir, 0o755); err != nil {
			return err
		}
	}
	var err error
	if opt.minSplitB, err = parseSize(opt.MinSplit); err != nil {
		return err
	}
	if bps, err := parseSize(opt.MaxSpeed); err != nil {
		return err
	} else if bps > 0 {
		opt.limiter = rate.NewLimiter(rate.Limit(bps), 256*1024)
	}
	for _, j := range jobs {
		j.opt.limiter = opt.limiter
		j.opt.minSplitB = opt.minSplitB
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ui := NewUI(opt.Quiet || opt.Silent)
	ui.silent = opt.Silent
	ui.showError = opt.ShowError
	ui.Start()

	var tracker *SessionTracker
	var stopSave chan struct{}
	if opt.SaveSession != "" {
		tracker = newSessionTracker(opt.SaveSession)
		stopSave = make(chan struct{})
		go func() {
			t := time.NewTicker(5 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					if _, err := tracker.save(); err != nil {
						ui.Warn("保存会话失败: %v", err)
					}
				case <-stopSave:
					return
				}
			}
		}()
	}

	sem := make(chan struct{}, opt.MaxJobs)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failed []string

	var bt *BTClient
	var btErr error
	var btOnce sync.Once
	getBT := func() (*BTClient, error) {
		btOnce.Do(func() { bt, btErr = NewBTClient(opt) })
		return bt, btErr
	}

	for _, j := range jobs {
		a := normalizeArg(j.src)
		jopt := j.opt
		low := strings.ToLower(a)
		isBT := strings.HasPrefix(low, "magnet:") || (strings.HasSuffix(low, ".torrent") && !strings.Contains(low, "://"))
		isFTP := strings.HasPrefix(low, "ftp://") || strings.HasPrefix(low, "ftps://")
		isSFTP := strings.HasPrefix(low, "sftp://")
		isHLS := strings.HasSuffix(low, ".m3u8")
		isMetalink := strings.HasSuffix(low, ".metalink") || strings.HasSuffix(low, ".meta4")
		kind := "HTTP"
		switch {
		case isBT:
			kind = " BT "
		case isFTP:
			kind = " FTP"
		case isSFTP:
			kind = "SFTP"
		case isHLS:
			kind = " HLS"
		case isMetalink:
			kind = "META"
		}
		custom := isCustomRequest(jopt) || jopt.Head
		task := ui.NewTask(displayName(a), kind)
		if tracker != nil && !custom {
			// 单连接请求任务不入会话: 其方法/请求体不做持久化 (可能含敏感数据), resume 无法忠实恢复
			tracker.add(task, entryFor(a, isBT, jopt))
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				task.Fail(ctx.Err())
				return
			}
			defer func() { <-sem }()
			if tracker != nil {
				tracker.markStarted(task)
			}
			task.SetState(StateActive)
			tctx := ctx
			if jopt.MaxTime > 0 { // curl --max-time: 单任务总超时
				var cancel2 context.CancelFunc
				tctx, cancel2 = context.WithTimeout(ctx, time.Duration(jopt.MaxTime*float64(time.Second)))
				defer cancel2()
			}
			var err error
			switch {
			case isBT && custom:
				err = fmt.Errorf("curl 请求参数 (-X/--data/-F/-I/--include) 不适用于 BT 任务")
			case isBT:
				var c *BTClient
				if c, err = getBT(); err == nil {
					err = c.Download(tctx, a, task, ui)
				}
			case (isFTP || isSFTP) && custom:
				err = fmt.Errorf("curl 请求参数 (-X/--data/-F/-I/--include) 不适用于 FTP/SFTP 任务")
			case isFTP:
				err = DownloadFTP(tctx, a, jopt, task, ui)
			case isSFTP:
				err = DownloadSFTP(tctx, a, jopt, task, ui)
			case (isHLS || isMetalink) && custom:
				err = fmt.Errorf("curl 请求参数 (-X/--data/-F/-I/--include) 不适用于 HLS/Metalink 任务")
			case isHLS:
				err = DownloadHLS(tctx, a, jopt, task, ui)
			case isMetalink:
				err = DownloadMetalink(tctx, a, jopt, task, ui)
			case strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://"):
				err = DownloadHTTP(tctx, a, jopt, task, ui)
			default:
				err = fmt.Errorf("不支持的协议: %q", a)
			}
			if err != nil {
				task.Fail(err)
				mu.Lock()
				failed = append(failed, fmt.Sprintf("%s: %v", a, err))
				mu.Unlock()
			} else {
				task.SetState(StateDone)
			}
		}()
	}
	if tracker != nil {
		// 立即保存一次, 进程随即被杀也能留下任务列表
		if _, err := tracker.save(); err != nil {
			ui.Warn("保存会话失败: %v", err)
		}
	}
	wg.Wait()
	var pending int
	if tracker != nil {
		close(stopSave)
		if pending, err = tracker.save(); err != nil {
			ui.Warn("保存会话失败: %v", err)
		}
	}
	ui.Stop()
	if bt != nil {
		bt.Close()
	}

	ui.Summary()
	if len(failed) == 0 {
		pterm.Success.Printfln("全部完成 %d/%d", len(jobs), len(jobs))
	} else {
		pterm.Error.Printfln("完成 %d/%d, 失败 %d", len(jobs)-len(failed), len(jobs), len(failed))
	}
	if ctx.Err() != nil {
		if tracker != nil {
			pterm.Warning.Printfln("已中断, %d 个未完成任务已保存到 %s, 运行 goria resume 恢复", pending, opt.SaveSession)
		} else {
			pterm.Warning.Println("已中断, 再次运行相同命令即可断点续传")
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d 个任务失败", len(failed))
	}
	return nil
}

func entryFor(src string, isBT bool, opt *Options) SessionEntry {
	kind := "http"
	if isBT {
		kind = "bt"
	}
	return SessionEntry{
		GID:      gidOf(src),
		URI:      src,
		Kind:     kind,
		Status:   "waiting",
		Dir:      opt.Dir,
		Out:      opt.Out,
		Checksum: opt.Checksum,
		Headers:  opt.Headers,
	}
}

func buildResumeJobs(s *Session, opt *Options, extra []string) []job {
	seen := make(map[string]bool)
	var jobs []job
	for _, e := range s.Entries {
		gid := e.GID
		if gid == "" {
			gid = gidOf(e.URI)
		}
		if seen[gid] {
			continue
		}
		seen[gid] = true
		o := *opt
		o.Out = e.Out
		o.Checksum = e.Checksum
		if len(e.Headers) > 0 {
			o.Headers = e.Headers
		}
		if e.Kind == "bt" {
			// BTClient 的 DataDir 是全局的, 无法按任务恢复原目录
			if e.Dir != "" && e.Dir != opt.Dir {
				pterm.Warning.Printfln("%s: BT 任务原目录 %s 与当前目录 %s 不同, 使用当前目录", displayName(e.URI), e.Dir, opt.Dir)
			}
		} else if e.Dir != "" {
			o.Dir = e.Dir
		}
		jobs = append(jobs, job{src: e.URI, opt: &o})
	}
	for _, a := range extra {
		a = normalizeArg(a)
		if gid := gidOf(a); !seen[gid] {
			seen[gid] = true
			jobs = append(jobs, job{src: a, opt: opt})
		}
	}
	return jobs
}

// normalizeArg 清理参数: 去掉空白、BOM、Windows cmd 下残留的引号; 无协议头的地址默认补 https://
func normalizeArg(a string) string {
	a = strings.TrimSpace(strings.TrimPrefix(a, "\ufeff"))
	for len(a) >= 2 && (a[0] == '\'' || a[0] == '"') {
		a = strings.Trim(a, "'\"")
		a = strings.TrimSpace(a)
	}
	a = strings.Trim(a, "'\"")
	low := strings.ToLower(a)
	if strings.Contains(low, "://") || strings.HasPrefix(low, "magnet:") {
		return a
	}
	if _, err := os.Stat(a); err == nil { // 本地 .torrent 文件
		return a
	}
	if strings.Contains(a, ".") && !strings.ContainsAny(a, " \\") {
		return "https://" + a
	}
	return a
}

func displayName(a string) string {
	if strings.HasPrefix(a, "magnet:") {
		if i := strings.Index(a, "dn="); i >= 0 {
			n := a[i+3:]
			if j := strings.Index(n, "&"); j >= 0 {
				n = n[:j]
			}
			return n
		}
		return "magnet"
	}
	return filepath.Base(strings.SplitN(a, "?", 2)[0])
}

func readLines(path string) ([]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var out []string
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

func parseSize(s string) (int64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" || s == "0" {
		return 0, nil
	}
	mul := int64(1)
	switch {
	case strings.HasSuffix(s, "G"):
		mul, s = 1<<30, strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "M"):
		mul, s = 1<<20, strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "K"):
		mul, s = 1<<10, strings.TrimSuffix(s, "K")
	}
	var n float64
	if _, err := fmt.Sscanf(s, "%g", &n); err != nil {
		return 0, fmt.Errorf("无效大小: %q", s)
	}
	return int64(n * float64(mul)), nil
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
