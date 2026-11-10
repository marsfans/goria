package main

// SFTP 下载 (对齐 aria2): 每段独立打开文件句柄, ReadAt 按偏移取数,
// 可分片可续传; Stat 的大小与修改时间作控制文件校验。
// 认证依次尝试: 密码 (URL userinfo 或 -u)、私钥 (--sftp-private-key 及
// ~/.ssh/id_ed25519、id_rsa、id_ecdsa)、SSH agent (SSH_AUTH_SOCK)。
// 主机密钥: 有 ~/.ssh/known_hosts 时严格校验, 没有则跳过并提示一次。
// 代理仅支持 socks5 (x/net/proxy 直拨), http 代理会提示后直连。

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	xproxy "golang.org/x/net/proxy"
)

type sftpTarget struct {
	host       string
	port       int
	user, pass string
	remotePath string
}

func parseSFTPTarget(rawurl string, opt *Options) (*sftpTarget, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	t := &sftpTarget{host: u.Hostname(), port: 22}
	if p := u.Port(); p != "" {
		if t.port, err = strconv.Atoi(p); err != nil {
			return nil, fmt.Errorf("SFTP 端口无效: %s", p)
		}
	}
	if t.host == "" {
		return nil, fmt.Errorf("SFTP 地址缺少主机名: %s", rawurl)
	}
	if u.User != nil {
		t.user = u.User.Username()
		t.pass, _ = u.User.Password()
	}
	if opt.User != "" {
		t.user, t.pass, _ = strings.Cut(opt.User, ":")
	}
	if t.user == "" {
		return nil, fmt.Errorf("SFTP 需要用户名 (URL userinfo 或 -u): %s", rawurl)
	}
	p, err := url.PathUnescape(u.Path)
	if err != nil {
		p = u.Path
	}
	t.remotePath = p // SFTP 路径按服务器绝对路径使用, 不剥前导 /
	if t.remotePath == "" || strings.HasSuffix(t.remotePath, "/") {
		return nil, fmt.Errorf("SFTP 地址指向目录, 暂不支持目录下载: %s", rawurl)
	}
	return t, nil
}

func sftpAuthMethods(opt *Options) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	// 私钥: 显式指定必须可加载; 默认路径加载得动才用
	tryKey := func(p string, required bool) error {
		b, err := os.ReadFile(p)
		if err != nil {
			if required {
				return fmt.Errorf("--sftp-private-key: %w", err)
			}
			return nil
		}
		signer, err := ssh.ParsePrivateKey(b)
		if err != nil {
			if required {
				return fmt.Errorf("--sftp-private-key %s: %w (暂不支持带口令的私钥)", p, err)
			}
			return nil
		}
		methods = append(methods, ssh.PublicKeys(signer))
		return nil
	}
	if opt.SFTPKey != "" {
		if err := tryKey(opt.SFTPKey, true); err != nil {
			return nil, err
		}
	} else if home, err := os.UserHomeDir(); err == nil {
		for _, n := range []string{"id_ed25519", "id_rsa", "id_ecdsa"} {
			tryKey(filepath.Join(home, ".ssh", n), false)
		}
	}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}
	return methods, nil
}

// dial 返回 sftp 客户端与底层 ssh 客户端: 关闭时必须先关 ssh 连接,
// 否则 sftp.Client.Close 会等收发循环退出而挂死 (pkg/sftp 已知行为)
func (t *sftpTarget) dial(ctx context.Context, opt *Options, ui *UI) (*sftp.Client, *ssh.Client, error) {
	methods, err := sftpAuthMethods(opt)
	if err != nil {
		return nil, nil, err
	}
	if t.pass != "" {
		methods = append([]ssh.AuthMethod{ssh.Password(t.pass)}, methods...)
	}
	if len(methods) == 0 {
		return nil, nil, fmt.Errorf("SFTP 无可用认证方式: 需要密码 (URL userinfo 或 -u)、私钥或 SSH agent")
	}
	var hk ssh.HostKeyCallback
	if home, herr := os.UserHomeDir(); herr == nil {
		if cb, kerr := knownhosts.New(filepath.Join(home, ".ssh", "known_hosts")); kerr == nil {
			hk = cb
		}
	}
	if hk == nil {
		ui.Warn("未找到可用的 ~/.ssh/known_hosts, 本次不校验 SFTP 主机密钥")
		hk = ssh.InsecureIgnoreHostKey()
	}
	timeout := 30 * time.Second
	if opt.ConnectTimeout > 0 {
		timeout = time.Duration(opt.ConnectTimeout * float64(time.Second))
	}
	cfg := &ssh.ClientConfig{User: t.user, Auth: methods, HostKeyCallback: hk, Timeout: timeout}
	addr := net.JoinHostPort(t.host, strconv.Itoa(t.port))
	network := "tcp"
	if opt.IPv4 {
		network = "tcp4"
	} else if opt.IPv6 {
		network = "tcp6"
	}
	var conn net.Conn
	if opt.Proxy != "" {
		pu, perr := url.Parse(opt.Proxy)
		if perr == nil && pu.Scheme == "socks5" {
			var auth *xproxy.Auth
			if pu.User != nil {
				pw, _ := pu.User.Password()
				auth = &xproxy.Auth{User: pu.User.Username(), Password: pw}
			}
			sd, derr := xproxy.SOCKS5("tcp", pu.Host, auth, &net.Dialer{Timeout: timeout})
			if derr != nil {
				return nil, nil, fmt.Errorf("socks5 代理: %w", derr)
			}
			conn, err = sd.Dial(network, addr)
		} else {
			ui.Warn("SFTP 仅支持 socks5 代理, 已直连")
		}
		if err != nil {
			return nil, nil, err
		}
	}
	if conn == nil {
		d := &net.Dialer{Timeout: timeout}
		if conn, err = d.DialContext(ctx, network, addr); err != nil {
			return nil, nil, err
		}
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("SSH 握手失败: %w", err)
	}
	sshClient := ssh.NewClient(sc, chans, reqs)
	client, err := sftp.NewClient(sshClient)
	if err != nil {
		sc.Close()
		return nil, nil, err
	}
	return client, sshClient, nil
}

func DownloadSFTP(ctx context.Context, rawurl string, opt *Options, task *Task, ui *UI) error {
	o := *opt
	opt = &o
	if opt.Range != "" || opt.ContinueAt != "" {
		return fmt.Errorf("--range/--continue-at 仅适用于 HTTP")
	}
	tgt, err := parseSFTPTarget(rawurl, opt)
	if err != nil {
		return err
	}
	client, sshClient, err := tgt.dial(ctx, opt, ui)
	if err != nil {
		return err
	}
	defer client.Close()    // 后关 (defer LIFO): 先关 ssh 连接, sftp 的 Close 才不会挂死
	defer sshClient.Close() // 先执行
	fi, err := client.Stat(tgt.remotePath)
	if err != nil {
		return fmt.Errorf("SFTP 读取文件信息失败: %w", err)
	}
	if fi.IsDir() {
		return fmt.Errorf("SFTP 地址指向目录, 暂不支持目录下载: %s", rawurl)
	}
	size := fi.Size()
	validator := strconv.FormatInt(fi.ModTime().Unix(), 10)

	name := path.Base(tgt.remotePath)
	if opt.Out != "" {
		name = opt.Out
	}
	fetch := func(ctx2 context.Context, fh *os.File, s *Segment, mu *sync.Mutex) error {
		f, err := client.Open(tgt.remotePath)
		if err != nil {
			return err
		}
		defer f.Close()
		mu.Lock()
		off := s.Start + s.Done
		mu.Unlock()
		var r io.Reader
		if s.End >= 0 {
			r = io.NewSectionReader(f, off, s.End-off+1)
		} else {
			r = io.NewSectionReader(f, off, 1<<62)
		}
		return pumpSegment(ctx2, r, fh, opt, s, task, mu)
	}
	return runSegmentedDownload(ctx, rawurl, name, size, validator, opt, task, ui, fetch)
}
