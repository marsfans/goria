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

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/time/rate"
)

type Options struct {
	Dir       string   `mapstructure:"dir"`
	Out       string   `mapstructure:"out"`
	Split     int      `mapstructure:"split"`
	MaxJobs   int      `mapstructure:"max-concurrent-downloads"`
	MaxSpeed  string   `mapstructure:"max-speed"`
	Headers   []string `mapstructure:"header"`
	UserAgent string   `mapstructure:"user-agent"`
	Retries   int      `mapstructure:"max-tries"`
	MinSplit  string   `mapstructure:"min-split-size"`
	InputFile string   `mapstructure:"input-file"`
	SeedRatio float64  `mapstructure:"seed-ratio"`
	BTListen  int      `mapstructure:"listen-port"`
	Checksum  string   `mapstructure:"checksum"`
	Insecure  bool     `mapstructure:"insecure"`
	Proxy     string   `mapstructure:"all-proxy"`
	Quiet     bool     `mapstructure:"quiet"`

	limiter   *rate.Limiter
	minSplitB int64
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
	// 让子命令也能读取根命令的 flag 默认值
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		return initConfig(root.Flags())
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
	if opt.MaxJobs < 1 {
		opt.MaxJobs = 1
	}
	if err := os.MkdirAll(opt.Dir, 0o755); err != nil {
		return err
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

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ui := NewUI(opt.Quiet)
	ui.Start()

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

	for _, a := range args {
		a := normalizeArg(a)
		low := strings.ToLower(a)
		isBT := strings.HasPrefix(low, "magnet:") || (strings.HasSuffix(low, ".torrent") && !strings.Contains(low, "://"))
		kind := "HTTP"
		if isBT {
			kind = " BT "
		}
		task := ui.NewTask(displayName(a), kind)
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
			task.SetState(StateActive)
			var err error
			switch {
			case isBT:
				var c *BTClient
				if c, err = getBT(); err == nil {
					err = c.Download(ctx, a, task, ui)
				}
			case strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://"):
				err = DownloadHTTP(ctx, a, opt, task, ui)
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
	wg.Wait()
	ui.Stop()
	if bt != nil {
		bt.Close()
	}

	ui.Summary()
	if len(failed) == 0 {
		pterm.Success.Printfln("全部完成 %d/%d", len(args), len(args))
	} else {
		pterm.Error.Printfln("完成 %d/%d, 失败 %d", len(args)-len(failed), len(args), len(failed))
	}
	if ctx.Err() != nil {
		pterm.Warning.Println("已中断, 再次运行相同命令即可断点续传")
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d 个任务失败", len(failed))
	}
	return nil
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
