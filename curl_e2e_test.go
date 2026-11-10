package main

// 第二批端到端测试: 覆盖首批只做了接线、未实测的参数
// (--cacert/--cert/--key mTLS、--connect-timeout、--max-time、-6、
// --proxy 转发与别名合并、--retry-delay 计时、-v/-s 输出、--create-dirs)

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// ---------- 测试用 CA 与证书 ----------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "goria-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) issue(t *testing.T, serial int64, server bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "goria-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func writeFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestMTLS 用自签 CA 搭一个要求客户端证书的 HTTPS 服务器, 验证
// --cacert (校验服务端) 与 --cert/--key (出示客户端证书) 的完整握手,
// 以及缺客户端证书 / 缺 CA 时确实失败 (证明不是走 Insecure 绕过去的)
func TestMTLS(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	caPath := writeFile(t, dir, "ca.pem", ca.pem)
	srvCertPEM, srvKeyPEM := ca.issue(t, 2, true)
	cliCertPEM, cliKeyPEM := ca.issue(t, 3, false)
	cliCertPath := writeFile(t, dir, "client.crt", cliCertPEM)
	cliKeyPath := writeFile(t, dir, "client.key", cliKeyPEM)

	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.pem)
	content := []byte("mtls-content")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "file.bin", time.Now(), bytes.NewReader(content))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	})
	go http.Serve(tlsLn, handler)
	defer tlsLn.Close()
	u := "https://" + ln.Addr().String() + "/file.bin"
	ui := NewUI(true)

	// 完整参数: 应成功
	dlDir := t.TempDir()
	opt := &Options{Dir: dlDir, CACert: caPath, Cert: cliCertPath, Key: cliKeyPath}
	if err := DownloadHTTP(context.Background(), u, opt, dlTask(ui), ui); err != nil {
		t.Fatalf("mTLS 下载失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dlDir, "file.bin")); !bytes.Equal(b, content) {
		t.Fatalf("内容错误: %q", b)
	}
	// 缺客户端证书: 握手应失败
	opt2 := &Options{Dir: t.TempDir(), CACert: caPath}
	if err := DownloadHTTP(context.Background(), u, opt2, dlTask(ui), ui); err == nil {
		t.Fatal("缺客户端证书应失败")
	}
	// 缺 CA (系统根不认自签): 应失败
	opt3 := &Options{Dir: t.TempDir(), Cert: cliCertPath, Key: cliKeyPath}
	if err := DownloadHTTP(context.Background(), u, opt3, dlTask(ui), ui); err == nil {
		t.Fatal("缺 --cacert 时自签服务端应校验失败")
	}
	// 坏的 CA 文件: 应在建客户端时报错
	opt4 := &Options{Dir: t.TempDir(), CACert: writeFile(t, dir, "bad.pem", []byte("not pem"))}
	if err := DownloadHTTP(context.Background(), u, opt4, dlTask(ui), ui); err == nil {
		t.Fatal("坏的 --cacert 应报错")
	}
}

// TestConnectTimeoutStalledTLS: 裸 TCP 接受连接后不说话, TLS 握手会卡住;
// --connect-timeout 同时作用于握手超时, 应在远小于默认 10s 内报错
func TestConnectTimeoutStalledTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			io.Copy(io.Discard, c) // 读完为止, 永不回话
		}
	}()
	opt := &Options{Dir: t.TempDir(), ConnectTimeout: 0.3}
	start := time.Now()
	err = DownloadHTTP(context.Background(), "https://"+ln.Addr().String()+"/x", opt, dlTask(NewUI(true)), NewUI(true))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("握手卡死应报错")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("--connect-timeout 0.3 未生效, 耗时 %v", elapsed)
	}
}

// TestMaxTime: 经 runJobs 全路径, 服务器 3s 才响应, --max-time 0.4 应中断任务并报错
func TestMaxTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.Write([]byte("slow"))
	}))
	defer srv.Close()
	opt := &Options{Dir: t.TempDir(), MaxTime: 0.4, Quiet: true}
	start := time.Now()
	err := runJobs(opt, []job{{src: srv.URL + "/slow", opt: opt}})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("--max-time 到期应使任务失败")
	}
	if elapsed > 2500*time.Millisecond {
		t.Fatalf("--max-time 未生效, 耗时 %v", elapsed)
	}
}

// TestIPv6Download: 在 [::1] 上起服务, -6 强制 tcp6 应能下载; 环境无 IPv6 时跳过
func TestIPv6Download(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("环境不支持 IPv6: %v", err)
	}
	content := []byte("ipv6-content")
	s := &http.Server{Handler: serveContentHandler(content, time.Now())}
	go s.Serve(ln)
	defer s.Close()
	dir := t.TempDir()
	opt := &Options{Dir: dir, IPv6: true}
	u := "http://" + ln.Addr().String() + "/file.bin"
	if err := DownloadHTTP(context.Background(), u, opt, dlTask(NewUI(true)), NewUI(true)); err != nil {
		t.Fatalf("-6 下载失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "file.bin")); !bytes.Equal(b, content) {
		t.Fatalf("内容错误: %q", b)
	}
}

// TestProxyForward: 极简转发代理, 验证请求确经代理 (代理计数) 且内容正确;
// 目标用 http:// (代理绝对 URI 形态)
func TestProxyForward(t *testing.T) {
	content := []byte("via-proxy")
	target := httptest.NewServer(serveContentHandler(content, time.Now()))
	defer target.Close()
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), nil)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		for k, vs := range r.Header {
			for _, v := range vs {
				outReq.Header.Add(k, v)
			}
		}
		resp, err := http.DefaultClient.Do(outReq)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	defer proxy.Close()
	dir := t.TempDir()
	opt := &Options{Dir: dir, Proxy: proxy.URL}
	if err := DownloadHTTP(context.Background(), target.URL+"/file.bin", opt, dlTask(NewUI(true)), NewUI(true)); err != nil {
		t.Fatalf("经代理下载失败: %v", err)
	}
	if hits.Load() == 0 {
		t.Fatal("请求没有经过代理")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "file.bin")); !bytes.Equal(b, content) {
		t.Fatalf("内容错误: %q", b)
	}
}

// TestApplyCurlAliases: 别名经 pflag+viper 解析后并入主参数
func TestApplyCurlAliases(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.String("limit-rate", "", "")
	fs.String("proxy", "", "")
	fs.String("output-dir", "", "")
	fs.Int("parallel-max", 0, "")
	fs.StringP("agent", "A", "", "")
	fs.Int("retry", -1, "")
	if err := viper.BindPFlags(fs); err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"--proxy", "http://127.0.0.1:8080", "--limit-rate", "2M",
		"--output-dir", "/tmp/dl", "--parallel-max", "3", "-A", "AgentX", "--retry", "7"}); err != nil {
		t.Fatal(err)
	}
	opt := &Options{}
	applyCurlAliases(opt)
	if opt.Proxy != "http://127.0.0.1:8080" || opt.MaxSpeed != "2M" || opt.Dir != "/tmp/dl" ||
		opt.MaxJobs != 3 || opt.UserAgent != "AgentX" || opt.Retries != 7 {
		t.Fatalf("别名并入错误: %+v", opt)
	}
}

// TestRetryDelayTiming: 首次探测返回 500 后重试; 自定义 --retry-delay 0.2
// 应让总耗时落在 [0.18s, 0.9s) —— 默认退避是 1s, 落在此区间证明自定义值生效
func TestRetryDelayTiming(t *testing.T) {
	content := []byte("retry-content")
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			http.Error(w, "boom", 500)
			return
		}
		http.ServeContent(w, r, "file.bin", time.Now(), bytes.NewReader(content))
	}))
	defer srv.Close()
	dir := t.TempDir()
	opt := &Options{Dir: dir, Retries: 3, RetryDelay: 0.2}
	start := time.Now()
	err := DownloadHTTP(context.Background(), srv.URL+"/file.bin", opt, dlTask(NewUI(true)), NewUI(true))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("重试后应成功: %v", err)
	}
	if elapsed < 180*time.Millisecond || elapsed >= 900*time.Millisecond {
		t.Fatalf("--retry-delay 0.2 未按预期生效, 耗时 %v", elapsed)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "file.bin")); !bytes.Equal(b, content) {
		t.Fatalf("内容错误: %q", b)
	}
}

// TestVerboseAndSilent: -v 的日志确实产生且敏感头脱敏; -s 丢普通日志, -S 保留错误
func TestVerboseAndSilent(t *testing.T) {
	content := []byte("v-content")
	srv := httptest.NewServer(serveContentHandler(content, time.Now()))
	defer srv.Close()

	// -v: 下载后 UI 日志里应有请求行
	ui := NewUI(true)
	opt := &Options{Dir: t.TempDir(), Verbose: true, Headers: []string{"Authorization: Bearer sekret"}}
	if err := DownloadHTTP(context.Background(), srv.URL+"/file.bin", opt, dlTask(ui), ui); err != nil {
		t.Fatal(err)
	}
	ui.mu.Lock()
	logs := strings.Join(ui.logs, "\n")
	ui.mu.Unlock()
	if !strings.Contains(logs, "GET") || !strings.Contains(logs, "206") {
		t.Fatalf("-v 应输出请求/响应行, 实际日志: %q", logs)
	}
	// verboseHeaders 脱敏
	ui2 := NewUI(true)
	h := http.Header{"Authorization": []string{"Bearer sekret"}, "X-Ok": []string{"1"}}
	verboseHeaders(ui2, &Options{Verbose: true}, ">", h)
	joined := strings.Join(ui2.logs, "\n")
	if strings.Contains(joined, "sekret") || !strings.Contains(joined, "***") || !strings.Contains(joined, "X-Ok") {
		t.Fatalf("-v 脱敏错误: %q", joined)
	}

	// -s: 普通日志被丢弃; 错误日志默认也丢, 开 -S 后保留
	ui3 := NewUI(true)
	ui3.silent = true
	ui3.Info("info")
	ui3.Success("ok")
	ui3.Warn("warn")
	ui3.Error("err-hidden")
	if len(ui3.logs) != 0 {
		t.Fatalf("-s 应丢弃全部普通日志, 实际 %q", ui3.logs)
	}
	ui3.showError = true
	ui3.Error("err-shown")
	if len(ui3.logs) != 1 || !strings.Contains(ui3.logs[0], "err-shown") {
		t.Fatalf("-s -S 应保留错误日志, 实际 %q", ui3.logs)
	}
}

// TestHTTP2Negotiated: goria 的客户端 (克隆 DefaultTransport, 自带 ForceAttemptHTTP2)
// 即使设置了自定义 DialContext 与 TLS 配置, 对支持 h2 的 HTTPS 服务器也应协商出 HTTP/2
func TestHTTP2Negotiated(t *testing.T) {
	var serverProto atomic.Value
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverProto.Store(r.Proto)
		w.Write([]byte("h2-body"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	// Insecure 会让 newHTTPClient 设置自定义 TLSClientConfig —— 正是容易弄丢 h2 的组合
	c, err := newHTTPClient(&Options{Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("客户端应协商 HTTP/2, 实际 %s", resp.Proto)
	}
	if p, _ := serverProto.Load().(string); p != "HTTP/2.0" {
		t.Fatalf("服务端应看到 HTTP/2, 实际 %s", p)
	}
	// 完整下载路径同样可用
	dir := t.TempDir()
	opt := &Options{Dir: dir, Insecure: true, Out: "h2.txt"}
	// 该测试服务器不支持 Range, 走单分片; 文件名由 -o 指定
	srv2 := httptest.NewTLSServer(serveContentHandler([]byte("h2-content"), time.Now()))
	defer srv2.Close()
	if err := DownloadHTTP(context.Background(), srv2.URL+"/h2.txt", opt, dlTask(NewUI(true)), NewUI(true)); err != nil {
		t.Fatalf("h2 服务器下载失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "h2.txt")); string(b) != "h2-content" {
		t.Fatalf("内容错误: %q", b)
	}
}

// TestCreateDirs: -o 含多级子路径时 --create-dirs 自动建目录并落盘
func TestCreateDirs(t *testing.T) {
	content := []byte("nested")
	srv := httptest.NewServer(serveContentHandler(content, time.Now()))
	defer srv.Close()
	dir := t.TempDir()
	opt := &Options{Dir: dir, Out: "a/b/c/out.bin", CreateDirs: true}
	if err := DownloadHTTP(context.Background(), srv.URL+"/file.bin", opt, dlTask(NewUI(true)), NewUI(true)); err != nil {
		t.Fatalf("--create-dirs 下载失败: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "a", "b", "c", "out.bin")); err != nil || !bytes.Equal(b, content) {
		t.Fatalf("嵌套输出错误: %q %v", b, err)
	}
}
