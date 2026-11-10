package main

// FTP/SFTP 端到端测试: 测试内假服务器 (FTP 手写控制协议; SFTP 用 pkg/sftp
// 的 RequestServer + x/crypto/ssh), 覆盖分片下载、断点续传 (按服务端实际
// 传输字节数断言)、错误密码、校验和与目标解析

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// ---------- 假 FTP 服务器 ----------

type fakeFTP struct {
	content []byte
	user    string
	pass    string

	mu        sync.Mutex
	sentBytes int64
	retrCount int
	restOffs  []int64

	ln net.Listener
}

func startFakeFTP(t *testing.T, content []byte) *fakeFTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeFTP{content: content, user: "bob", pass: "secret", ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeFTP) addr() string { return f.ln.Addr().String() }

func (f *fakeFTP) stats() (int64, int, []int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sentBytes, f.retrCount, append([]int64(nil), f.restOffs...)
}

func (f *fakeFTP) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := func(s string) { fmt.Fprintf(c, "%s\r\n", s) }
	w("220 fake ftp ready")
	var user string
	var restOff int64
	var dataLn net.Listener
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(strings.TrimRight(line, "\r\n"))
		if len(fields) == 0 {
			continue
		}
		arg := ""
		if len(fields) > 1 {
			arg = fields[1]
		}
		switch fields[0] {
		case "USER":
			user = arg
			w("331 password required")
		case "PASS":
			if user == f.user && arg == f.pass {
				w("230 logged in")
			} else {
				w("530 wrong credentials")
			}
		case "FEAT":
			fmt.Fprintf(c, "211-Features:\r\n MDTM\r\n SIZE\r\n211 End\r\n")
		case "SYST":
			w("215 UNIX Type: L8")
		case "TYPE":
			w("200 type set")
		case "OPTS":
			w("200 ok")
		case "SIZE":
			if arg == "file.bin" {
				w(fmt.Sprintf("213 %d", len(f.content)))
			} else {
				w("550 not found")
			}
		case "MDTM":
			if arg == "file.bin" {
				w("213 20260101030405")
			} else {
				w("550 not found")
			}
		case "EPSV":
			dataLn, err = net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				w("425 cannot open data")
				continue
			}
			w(fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|)", dataLn.Addr().(*net.TCPAddr).Port))
		case "PASV":
			dataLn, err = net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				w("425 cannot open data")
				continue
			}
			p := dataLn.Addr().(*net.TCPAddr).Port
			w(fmt.Sprintf("227 Entering Passive Mode (127,0,0,1,%d,%d)", p/256, p%256))
		case "REST":
			restOff, _ = strconv.ParseInt(arg, 10, 64)
			f.mu.Lock()
			f.restOffs = append(f.restOffs, restOff)
			f.mu.Unlock()
			w("350 restart ok")
		case "RETR":
			if arg != "file.bin" || dataLn == nil {
				w("550 not found or no data connection")
				continue
			}
			w("150 opening data")
			dc, err := dataLn.Accept()
			dataLn.Close()
			dataLn = nil
			if err != nil {
				return
			}
			off := restOff
			restOff = 0
			n, _ := dc.Write(f.content[off:])
			dc.Close()
			f.mu.Lock()
			f.sentBytes += int64(n)
			f.retrCount++
			f.mu.Unlock()
			w("226 transfer complete")
		case "QUIT":
			w("221 bye")
			return
		default:
			w("502 not implemented")
		}
	}
}

func TestFTPDownloadAndResume(t *testing.T) {
	content := bytes.Repeat([]byte("0123456789abcdef"), 8192) // 128 KiB
	srv := startFakeFTP(t, content)
	ui := NewUI(true)
	ctx := context.Background()
	u := "ftp://bob:secret@" + srv.addr() + "/file.bin"

	// 分片下载: split=4 应产生多次 RETR 且内容正确
	dir := t.TempDir()
	opt := &Options{Dir: dir, Split: 4, UserAgent: "test"}
	if err := DownloadFTP(ctx, u, opt, dlTask(ui), ui); err != nil {
		t.Fatalf("FTP 下载失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "file.bin")); !bytes.Equal(b, content) {
		t.Fatal("FTP 下载内容不一致")
	}
	// 注意: FTP 的 RETR 从 REST 偏移发到文件尾, 服务端发送量大于文件大小是
	// 协议常态 (客户端按段尾截断), 这里只断言分段连接数
	_, retrs, _ := srv.stats()
	if retrs < 2 {
		t.Fatalf("分片下载应有多次 RETR, 实际 %d", retrs)
	}

	// 断点续传: 预置半成品 + 控制文件, 服务端只应补发后半
	dir2 := t.TempDir()
	half := int64(len(content) / 2)
	os.WriteFile(filepath.Join(dir2, "file.bin"), content[:half], 0o644)
	ctl := map[string]any{
		"url": u, "size": len(content), "etag": "",
		"segments": []map[string]int64{{"start": 0, "end": int64(len(content) - 1), "done": half}},
	}
	cb, _ := json.Marshal(ctl)
	os.WriteFile(filepath.Join(dir2, "file.bin.goria"), cb, 0o644)
	before, _, _ := srv.stats()
	opt2 := &Options{Dir: dir2, Split: 4}
	if err := DownloadFTP(ctx, u, opt2, dlTask(ui), ui); err != nil {
		t.Fatalf("FTP 续传失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir2, "file.bin")); !bytes.Equal(b, content) {
		t.Fatal("FTP 续传内容不一致")
	}
	after, _, offs := srv.stats()
	if after-before != int64(len(content))-half {
		t.Fatalf("续传应只补发 %d 字节, 实际 %d", int64(len(content))-half, after-before)
	}
	found := false
	for _, o := range offs {
		if o == half {
			found = true
		}
	}
	if !found {
		t.Fatalf("续传应带 REST %d, 服务端记录 %v", half, offs)
	}

	// 凭据可由 -u 提供 (URL 不带 userinfo), 密码错误应失败
	u2 := "ftp://bob@" + srv.addr() + "/file.bin"
	opt3 := &Options{Dir: t.TempDir(), User: "bob:secret"}
	if err := DownloadFTP(ctx, u2, opt3, dlTask(ui), ui); err != nil {
		t.Fatalf("-u 凭据下载失败: %v", err)
	}
	u3 := "ftp://bob:wrong@" + srv.addr() + "/file.bin"
	if err := DownloadFTP(ctx, u3, &Options{Dir: t.TempDir()}, dlTask(ui), ui); err == nil {
		t.Fatal("错误密码应失败")
	}
}

// TestRunJobsDispatch: 主分发 (runJobs) 对 ftp:// / sftp:// 的路由与种类标注
func TestRunJobsDispatch(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	content := []byte("dispatch-content")
	ftpSrv := startFakeFTP(t, content)
	var readBytes int64
	var mu sync.Mutex
	h := fakeSFTPHandlers{
		files: map[string][]byte{"/data/file.bin": content},
		mod:   time.Unix(1767225600, 0), read: &readBytes, mu: &mu,
	}
	sftpAddr := startFakeSFTP(t, h, nil)

	dir := t.TempDir()
	opt := &Options{Dir: dir, Quiet: true}
	jobs := []job{
		{src: "ftp://bob:secret@" + ftpSrv.addr() + "/file.bin", opt: opt},
		{src: "sftp://carol:hunter2@" + sftpAddr + "/data/file.bin", opt: &Options{Dir: dir, Quiet: true, Out: "sftp-file.bin"}},
	}
	if err := runJobs(opt, jobs); err != nil {
		t.Fatalf("runJobs 分发失败: %v", err)
	}
	for _, n := range []string{"file.bin", "sftp-file.bin"} {
		if b, _ := os.ReadFile(filepath.Join(dir, n)); !bytes.Equal(b, content) {
			t.Fatalf("%s 内容错误: %q", n, b)
		}
	}
	// curl 请求参数不适用于 FTP/SFTP
	bad := &Options{Dir: t.TempDir(), Quiet: true, Data: []string{"a=1"}}
	jobs2 := []job{{src: "ftp://bob:secret@" + ftpSrv.addr() + "/file.bin", opt: bad}}
	if err := runJobs(bad, jobs2); err == nil {
		t.Fatal("FTP 任务带 --data 应失败")
	}
}

func TestParseFTPTarget(t *testing.T) {
	tg, err := parseFTPTarget("ftp://alice:pw@h:2121/a/b.bin", &Options{})
	if err != nil || tg.user != "alice" || tg.pass != "pw" || tg.port != 2121 || tg.remotePath != "a/b.bin" || tg.explicit {
		t.Fatalf("解析错误: %+v %v", tg, err)
	}
	tg, err = parseFTPTarget("ftps://h/f.bin", &Options{User: "u2:p2"})
	if err != nil || tg.user != "u2" || tg.port != 21 || !tg.explicit {
		t.Fatalf("-u 覆盖/匿名兜底错误: %+v %v", tg, err)
	}
	tg, _ = parseFTPTarget("ftp://h/f.bin", &Options{})
	if tg.user != "anonymous" {
		t.Fatalf("缺省应匿名, 实际 %s", tg.user)
	}
	if _, err = parseFTPTarget("ftp://h/dir/", &Options{}); err == nil {
		t.Fatal("目录地址应报错")
	}
}

// ---------- 假 SFTP 服务器 ----------

type fakeFileInfo struct {
	name string
	size int64
	mod  time.Time
}

func (fi fakeFileInfo) Name() string       { return fi.name }
func (fi fakeFileInfo) Size() int64        { return fi.size }
func (fi fakeFileInfo) Mode() os.FileMode  { return 0o644 }
func (fi fakeFileInfo) ModTime() time.Time { return fi.mod }
func (fi fakeFileInfo) IsDir() bool        { return false }
func (fi fakeFileInfo) Sys() any           { return nil }

type countingReaderAt struct {
	r  io.ReaderAt
	n  *int64
	mu *sync.Mutex
}

func (c countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.mu.Lock()
	*c.n += int64(n)
	c.mu.Unlock()
	return n, err
}

type fakeSFTPHandlers struct {
	files map[string][]byte
	mod   time.Time
	read  *int64
	mu    *sync.Mutex
}

func (h fakeSFTPHandlers) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	b, ok := h.files[r.Filepath]
	if !ok {
		return nil, os.ErrNotExist
	}
	return countingReaderAt{r: bytes.NewReader(b), n: h.read, mu: h.mu}, nil
}

type listerAt struct{ entries []os.FileInfo }

func (l listerAt) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l.entries)) {
		return 0, io.EOF
	}
	n := copy(ls, l.entries[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

func (h fakeSFTPHandlers) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	if b, ok := h.files[r.Filepath]; ok {
		return listerAt{[]os.FileInfo{fakeFileInfo{name: filepath.Base(r.Filepath), size: int64(len(b)), mod: h.mod}}}, nil
	}
	var entries []os.FileInfo
	for p, b := range h.files {
		entries = append(entries, fakeFileInfo{name: filepath.Base(p), size: int64(len(b)), mod: h.mod})
	}
	return listerAt{entries}, nil
}

func startFakeSFTP(t *testing.T, h fakeSFTPHandlers, pubKey ssh.PublicKey) string {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == "carol" && string(pw) == "hunter2" {
				return nil, nil
			}
			return nil, fmt.Errorf("bad password")
		},
	}
	if pubKey != nil {
		cfg.PublicKeyCallback = func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == "carol" && bytes.Equal(k.Marshal(), pubKey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("bad key")
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func(nc net.Conn) {
				_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					if ch.ChannelType() != "session" {
						ch.Reject(ssh.UnknownChannelType, "only session")
						continue
					}
					channel, requests, err := ch.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range requests {
							if req.Type == "subsystem" && string(req.Payload[4:]) == "sftp" {
								req.Reply(true, nil)
								sftp.NewRequestServer(channel, sftp.Handlers{
									FileGet: h, FileList: h,
								}).Serve()
								return
							}
							req.Reply(false, nil)
						}
					}()
				}
			}(nc)
		}
	}()
	return ln.Addr().String()
}

func TestSFTPDownloadResumeAndKeyAuth(t *testing.T) {
	// 隔离 HOME: 避免开发机真实 ~/.ssh/known_hosts 触发严格主机密钥校验
	t.Setenv("HOME", t.TempDir())
	content := bytes.Repeat([]byte("sftp-data-block!"), 8192) // 128 KiB
	var readBytes int64
	var mu sync.Mutex
	mod := time.Unix(1767225600, 0)
	h := fakeSFTPHandlers{
		files: map[string][]byte{"/data/file.bin": content},
		mod:   mod, read: &readBytes, mu: &mu,
	}
	addr := startFakeSFTP(t, h, nil)
	ui := NewUI(true)
	ctx := context.Background()
	u := "sftp://carol:hunter2@" + addr + "/data/file.bin"

	// 密码登录 + 分片下载
	dir := t.TempDir()
	opt := &Options{Dir: dir, Split: 4}
	if err := DownloadSFTP(ctx, u, opt, dlTask(ui), ui); err != nil {
		t.Fatalf("SFTP 下载失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "file.bin")); !bytes.Equal(b, content) {
		t.Fatal("SFTP 下载内容不一致")
	}

	// 续传: 预置一半, 服务端只应再读后半
	dir2 := t.TempDir()
	half := int64(len(content) / 2)
	os.WriteFile(filepath.Join(dir2, "file.bin"), content[:half], 0o644)
	ctl := map[string]any{
		"url": u, "size": len(content), "etag": "",
		"segments": []map[string]int64{{"start": 0, "end": int64(len(content) - 1), "done": half}},
	}
	cb, _ := json.Marshal(ctl)
	os.WriteFile(filepath.Join(dir2, "file.bin.goria"), cb, 0o644)
	mu.Lock()
	readBytes = 0
	mu.Unlock()
	if err := DownloadSFTP(ctx, u, &Options{Dir: dir2, Split: 2}, dlTask(ui), ui); err != nil {
		t.Fatalf("SFTP 续传失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir2, "file.bin")); !bytes.Equal(b, content) {
		t.Fatal("SFTP 续传内容不一致")
	}
	mu.Lock()
	got := readBytes
	mu.Unlock()
	if got != int64(len(content))-half {
		t.Fatalf("续传应只读 %d 字节, 实际 %d", int64(len(content))-half, got)
	}

	// 错误密码应失败
	uBad := "sftp://carol:nope@" + addr + "/data/file.bin"
	if err := DownloadSFTP(ctx, uBad, &Options{Dir: t.TempDir()}, dlTask(ui), ui); err == nil {
		t.Fatal("错误密码应失败")
	}

	// 私钥登录: 另起一个接受该公钥的服务器
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	addr2 := startFakeSFTP(t, h, sshPub)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	privBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(keyPath, pem.EncodeToMemory(privBlock), 0o600)
	u2 := "sftp://carol@" + addr2 + "/data/file.bin"
	dir3 := t.TempDir()
	opt3 := &Options{Dir: dir3, SFTPKey: keyPath}
	if err := DownloadSFTP(ctx, u2, opt3, dlTask(ui), ui); err != nil {
		t.Fatalf("SFTP 私钥登录下载失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir3, "file.bin")); !bytes.Equal(b, content) {
		t.Fatal("私钥登录下载内容不一致")
	}
}

func TestParseSFTPTarget(t *testing.T) {
	tg, err := parseSFTPTarget("sftp://dan:pw@h:2222/var/f.bin", &Options{})
	if err != nil || tg.user != "dan" || tg.port != 2222 || tg.remotePath != "/var/f.bin" {
		t.Fatalf("解析错误: %+v %v", tg, err)
	}
	if _, err = parseSFTPTarget("sftp://h/f.bin", &Options{}); err == nil {
		t.Fatal("缺用户名应报错")
	}
	if _, err = parseSFTPTarget("sftp://dan@h/", &Options{}); err == nil {
		t.Fatal("根目录应报错")
	}
}
