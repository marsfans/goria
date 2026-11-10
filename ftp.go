package main

// FTP / FTPS 下载 (对齐 aria2): 被动模式, 每段一条连接 (REST 偏移),
// SIZE 查大小、MDTM 作版本校验, 不支持时回落单连接整下。
// 凭据依次取 URL userinfo、-u/--user, 缺省匿名。仅单文件, 不下目录。
// 注意: --proxy 不适用于 FTP (协议层无此概念), 会提示后直连。

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jlaffaye/ftp"
)

type ftpTarget struct {
	host       string
	port       int
	user, pass string
	remotePath string
	explicit   bool // ftps:// 显式 TLS (AUTH TLS)
}

func parseFTPTarget(rawurl string, opt *Options) (*ftpTarget, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	t := &ftpTarget{host: u.Hostname(), port: 21, explicit: u.Scheme == "ftps"}
	if p := u.Port(); p != "" {
		if t.port, err = strconv.Atoi(p); err != nil {
			return nil, fmt.Errorf("FTP 端口无效: %s", p)
		}
	}
	if t.host == "" {
		return nil, fmt.Errorf("FTP 地址缺少主机名: %s", rawurl)
	}
	if u.User != nil {
		t.user = u.User.Username()
		t.pass, _ = u.User.Password()
	}
	if opt.User != "" { // -u 优先于 URL userinfo (与 HTTP 路径一致)
		t.user, t.pass, _ = strings.Cut(opt.User, ":")
	}
	if t.user == "" {
		t.user, t.pass = "anonymous", "anonymous@"
	}
	p, err := url.PathUnescape(u.Path)
	if err != nil {
		p = u.Path
	}
	t.remotePath = strings.TrimPrefix(p, "/")
	if t.remotePath == "" || strings.HasSuffix(t.remotePath, "/") {
		return nil, fmt.Errorf("FTP 地址指向目录, 暂不支持目录下载: %s", rawurl)
	}
	return t, nil
}

func (t *ftpTarget) dial(opt *Options) (*ftp.ServerConn, error) {
	timeout := 30 * time.Second
	if opt.ConnectTimeout > 0 {
		timeout = time.Duration(opt.ConnectTimeout * float64(time.Second))
	}
	dialFunc := func(network, address string) (net.Conn, error) {
		if opt.IPv4 {
			network = "tcp4"
		} else if opt.IPv6 {
			network = "tcp6"
		}
		d := &net.Dialer{Timeout: timeout}
		return d.Dial(network, address)
	}
	opts := []ftp.DialOption{
		ftp.DialWithTimeout(timeout),
		ftp.DialWithDialFunc(dialFunc),
	}
	if t.explicit {
		opts = append(opts, ftp.DialWithExplicitTLS(&tls.Config{
			InsecureSkipVerify: opt.Insecure,
			ServerName:         t.host,
		}))
	}
	c, err := ftp.Dial(net.JoinHostPort(t.host, strconv.Itoa(t.port)), opts...)
	if err != nil {
		return nil, err
	}
	if err := c.Login(t.user, t.pass); err != nil {
		c.Quit()
		return nil, fmt.Errorf("FTP 登录失败: %w", err)
	}
	return c, nil
}

func DownloadFTP(ctx context.Context, rawurl string, opt *Options, task *Task, ui *UI) error {
	o := *opt
	opt = &o
	if opt.Range != "" || opt.ContinueAt != "" {
		return fmt.Errorf("--range/--continue-at 仅适用于 HTTP")
	}
	tgt, err := parseFTPTarget(rawurl, opt)
	if err != nil {
		return err
	}
	if opt.Proxy != "" {
		ui.Warn("FTP 不使用 --proxy (协议不同), 已直连")
	}

	// 探测: 大小与修改时间 (服务器不支持则 size=-1 单连接)
	var size int64 = -1
	var validator string
	pc, err := tgt.dial(opt)
	if err != nil {
		return err
	}
	if sz, e := pc.FileSize(tgt.remotePath); e == nil {
		size = sz
	}
	if tm, e := pc.GetTime(tgt.remotePath); e == nil {
		validator = tm.UTC().Format(time.RFC3339)
	}
	pc.Quit()

	name := path.Base(tgt.remotePath)
	if opt.Out != "" {
		name = opt.Out
	}
	fetch := func(ctx2 context.Context, fh *os.File, s *Segment, mu *sync.Mutex) error {
		conn, err := tgt.dial(opt)
		if err != nil {
			return err
		}
		defer conn.Quit()
		mu.Lock()
		off := s.Start + s.Done
		mu.Unlock()
		resp, err := conn.RetrFrom(tgt.remotePath, uint64(off))
		if err != nil {
			return err
		}
		defer resp.Close()
		stop := make(chan struct{})
		defer close(stop)
		go func() { // ctx 取消时关数据连接, 解开阻塞的 Read
			select {
			case <-ctx2.Done():
				resp.Close()
			case <-stop:
			}
		}()
		return pumpSegment(ctx2, resp, fh, opt, s, task, mu)
	}
	return runSegmentedDownload(ctx, rawurl, name, size, validator, opt, task, ui, fetch)
}
