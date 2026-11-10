package main

// 协议选择端到端测试: --http1.1 强制、--http2 协商要求、
// --http3-only 真 QUIC 下载、--http3 失败回落 TCP

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// udpLoopbackOK 探测本环境能否发出 UDP 包: 部分沙箱 (如 hatch 机房出口策略)
// 连环回 UDP 的 sendto 都直接 EPERM, 那种环境里 QUIC 客户端无从工作,
// 需要真 QUIC 往返的用例只能跳过 (回落/拒绝类用例不受影响, 照常跑)
func udpLoopbackOK(t *testing.T) bool {
	t.Helper()
	srv, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer srv.Close()
	go func() {
		buf := make([]byte, 64)
		n, addr, err := srv.ReadFrom(buf)
		if err == nil {
			srv.WriteTo(buf[:n], addr)
		}
	}()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.WriteTo([]byte("ping"), srv.LocalAddr()); err != nil {
		return false
	}
	buf := make([]byte, 64)
	_, _, err = c.ReadFrom(buf)
	return err == nil
}

func TestHTTP11ForcedAndHTTP2Required(t *testing.T) {
	content := []byte("proto-content")
	var serverProto atomic.Value
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverProto.Store(r.Proto)
		http.ServeContent(w, r, "file.bin", time.Now(), bytes.NewReader(content))
	})
	// h2 服务器
	h2srv := httptest.NewUnstartedServer(handler)
	h2srv.EnableHTTP2 = true
	h2srv.StartTLS()
	defer h2srv.Close()
	// h1-only 服务器 (EnableHTTP2=false 时测试服务器 ALPN 只报 http/1.1)
	h1srv := httptest.NewTLSServer(handler)
	defer h1srv.Close()

	ui := NewUI(true)
	// --http1.1 对着 h2 服务器也只能谈出 1.1
	c, err := newHTTPClient(&Options{Insecure: true, HTTP11: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(h2srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Proto != "HTTP/1.1" {
		t.Fatalf("--http1.1 应强制 HTTP/1.1, 实际 %s", resp.Proto)
	}
	// --http2 对 h2 服务器: 下载成功
	dir := t.TempDir()
	opt := &Options{Dir: dir, Insecure: true, HTTP2: true}
	if err := DownloadHTTP(context.Background(), h2srv.URL+"/file.bin", opt, dlTask(ui), ui); err != nil {
		t.Fatalf("--http2 下载失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "file.bin")); !bytes.Equal(b, content) {
		t.Fatalf("内容错误: %q", b)
	}
	// --http2 对 h1-only 服务器: 应报协议不符
	opt2 := &Options{Dir: t.TempDir(), Insecure: true, HTTP2: true}
	err = DownloadHTTP(context.Background(), h1srv.URL+"/file.bin", opt2, dlTask(ui), ui)
	if !errors.Is(err, errProtoMismatch) {
		t.Fatalf("--http2 对 h1 服务器应报 errProtoMismatch, 实际 %v", err)
	}
	// 不带要求时 h1 服务器照常下载, 服务端看到 1.1
	dir3 := t.TempDir()
	opt3 := &Options{Dir: dir3, Insecure: true}
	if err := DownloadHTTP(context.Background(), h1srv.URL+"/file.bin", opt3, dlTask(ui), ui); err != nil {
		t.Fatal(err)
	}
	if p, _ := serverProto.Load().(string); p != "HTTP/1.1" {
		t.Fatalf("h1 服务器应看到 HTTP/1.1, 实际 %s", p)
	}
	// --http2 / --http3 用在明文 http 上应直接报错
	plain := httptest.NewServer(handler)
	defer plain.Close()
	for name, o := range map[string]*Options{
		"http2":     {Dir: t.TempDir(), HTTP2: true},
		"http3":     {Dir: t.TempDir(), HTTP3: true},
		"http3only": {Dir: t.TempDir(), HTTP3Only: true},
	} {
		if err := DownloadHTTP(context.Background(), plain.URL+"/file.bin", o, dlTask(ui), ui); err == nil {
			t.Errorf("%s 用在 http:// 应报错", name)
		}
	}
}

type stubTransport struct {
	calls  atomic.Int32
	fail   bool
	onReq  func(*http.Request)
	respCt string
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.calls.Add(1)
	if s.onReq != nil {
		s.onReq(req)
	}
	if s.fail {
		return nil, errors.New("stub failure")
	}
	return &http.Response{
		StatusCode: 200, Status: "200 OK", Proto: "HTTP/3.0", ProtoMajor: 3,
		Header: make(http.Header),
		Body:   io.NopCloser(strings.NewReader(s.respCt)),
	}, nil
}

// TestProtoFallbackTransport: 回落传输层的锁定与请求体重放逻辑 (不依赖真 QUIC)
func TestProtoFallbackTransport(t *testing.T) {
	// primary 失败 + 有 GetBody: fallback 应收到完整请求体; 之后锁定 fallback
	primary := &stubTransport{fail: true}
	var fallbackBody []byte
	fallback := &stubTransport{onReq: func(r *http.Request) {
		if r.Body != nil {
			fallbackBody, _ = io.ReadAll(r.Body)
		}
	}}
	ft := &protoFallbackTransport{primary: primary, fallback: fallback}
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/x", strings.NewReader("payload"))
	resp, err := ft.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("回落应成功: %v", err)
	}
	resp.Body.Close()
	if string(fallbackBody) != "payload" {
		t.Fatalf("fallback 收到的请求体错误: %q", fallbackBody)
	}
	req2, _ := http.NewRequest(http.MethodGet, "https://example.com/y", nil)
	resp2, err := ft.RoundTrip(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if primary.calls.Load() != 1 {
		t.Fatalf("锁定后不应再试 primary, 实际调用 %d 次", primary.calls.Load())
	}
	// primary 成功: 不碰 fallback
	p2, f2 := &stubTransport{}, &stubTransport{}
	ft2 := &protoFallbackTransport{primary: p2, fallback: f2}
	req3, _ := http.NewRequest(http.MethodGet, "https://example.com/z", nil)
	r3, err := ft2.RoundTrip(req3)
	if err != nil {
		t.Fatal(err)
	}
	r3.Body.Close()
	if f2.calls.Load() != 0 {
		t.Fatal("primary 成功时不应调用 fallback")
	}
	// 请求体不可重放 (无 GetBody): 直接报 primary 的错, 不回落
	p3 := &stubTransport{fail: true}
	f3 := &stubTransport{}
	ft3 := &protoFallbackTransport{primary: p3, fallback: f3}
	req4, _ := http.NewRequest(http.MethodPost, "https://example.com/w", io.NopCloser(strings.NewReader("x")))
	req4.GetBody = nil
	if _, err := ft3.RoundTrip(req4); err == nil {
		t.Fatal("不可重放时应返回 primary 错误")
	}
	if f3.calls.Load() != 0 {
		t.Fatal("不可重放时不应调用 fallback")
	}
}

// startH3Server 用测试 CA 起一个真 HTTP/3 服务器, 返回 URL 与服务端看到的协议记录
func startH3Server(t *testing.T, content []byte) (string, *atomic.Value, string) {
	t.Helper()
	ca := newTestCA(t)
	dir := t.TempDir()
	caPath := writeFile(t, dir, "ca.pem", ca.pem)
	srvCertPEM, srvKeyPEM := ca.issue(t, 2, true)
	cert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}})
	ln, err := quic.ListenAddrEarly("127.0.0.1:0", tlsConf, &quic.Config{})
	if err != nil {
		t.Fatalf("QUIC 监听失败 (环境可能不支持 UDP): %v", err)
	}
	var proto atomic.Value
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto.Store(r.Proto)
		http.ServeContent(w, r, "file.bin", time.Now(), bytes.NewReader(content))
	})
	srv := &http3.Server{Handler: handler}
	go srv.ServeListener(ln)
	t.Cleanup(func() { srv.Close() })
	return "https://" + ln.Addr().String() + "/file.bin", &proto, caPath
}

func TestHTTP3OnlyDownload(t *testing.T) {
	content := []byte("h3-content-0123456789")
	ui := NewUI(true)
	// --http3-only 对着纯 TCP 的 TLS 服务器应失败 (不回落) —— 不依赖 UDP 可用性
	tcpSrv := httptest.NewTLSServer(serveContentHandler(content, time.Now()))
	defer tcpSrv.Close()
	opt2 := &Options{Dir: t.TempDir(), Insecure: true, HTTP3Only: true}
	if err := DownloadHTTP(context.Background(), tcpSrv.URL+"/file.bin", opt2, dlTask(ui), ui); err == nil {
		t.Fatal("--http3-only 对 TCP 服务器应失败")
	}
	// 真 QUIC 往返需要本环境允许发 UDP
	if !udpLoopbackOK(t) {
		t.Skip("本环境禁止发出 UDP 包 (sendto EPERM), 跳过真 QUIC 下载用例")
	}
	u, proto, caPath := startH3Server(t, content)
	dir := t.TempDir()
	opt := &Options{Dir: dir, CACert: caPath, HTTP3Only: true, Split: 4}
	if err := DownloadHTTP(context.Background(), u, opt, dlTask(ui), ui); err != nil {
		t.Fatalf("--http3-only 下载失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "file.bin")); !bytes.Equal(b, content) {
		t.Fatalf("内容错误: %q", b)
	}
	if p, _ := proto.Load().(string); p != "HTTP/3.0" {
		t.Fatalf("服务端应看到 HTTP/3.0, 实际 %v", proto.Load())
	}
}

func TestHTTP3FallbackToTCP(t *testing.T) {
	content := []byte("fallback-content")
	// 纯 TCP TLS 服务器: --http3 先试 QUIC 失败后应回落并成功
	tcpSrv := httptest.NewTLSServer(serveContentHandler(content, time.Now()))
	defer tcpSrv.Close()
	ui := NewUI(true)
	dir := t.TempDir()
	opt := &Options{Dir: dir, Insecure: true, HTTP3: true}
	start := time.Now()
	if err := DownloadHTTP(context.Background(), tcpSrv.URL+"/file.bin", opt, dlTask(ui), ui); err != nil {
		t.Fatalf("--http3 回落失败: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("回落耗时过长: %v", elapsed)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "file.bin")); !bytes.Equal(b, content) {
		t.Fatalf("内容错误: %q", b)
	}
	// --http3 对真 h3 服务器直达 (不回落) 需要本环境允许发 UDP
	if !udpLoopbackOK(t) {
		t.Skip("本环境禁止发出 UDP 包 (sendto EPERM), 跳过真 QUIC 直达用例")
	}
	u, proto, caPath := startH3Server(t, content)
	dir2 := t.TempDir()
	opt2 := &Options{Dir: dir2, CACert: caPath, HTTP3: true}
	if err := DownloadHTTP(context.Background(), u, opt2, dlTask(ui), ui); err != nil {
		t.Fatalf("--http3 对 h3 服务器失败: %v", err)
	}
	if p, _ := proto.Load().(string); p != "HTTP/3.0" {
		t.Fatalf("应直达 HTTP/3, 服务端实际看到 %v", proto.Load())
	}
	if b, _ := os.ReadFile(filepath.Join(dir2, "file.bin")); !bytes.Equal(b, content) {
		t.Fatalf("内容错误: %q", b)
	}
	if !strings.HasPrefix(u, "https://") {
		t.Fatal("h3 URL 应为 https")
	}
}
