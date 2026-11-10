package main

// HTTP/3 支持 (quic-go/http3): Go 标准库没有 HTTP/3, 这里用 http3.Transport
// 作为 RoundTripper 接入现有 http.Client (cookie jar / 重定向 / 校验逻辑不变)。
// --http3-only: 全部请求走 QUIC; --http3: 先试 QUIC, 传输层失败则回落 TCP 并锁定,
// 后续请求 (含各分片) 不再重复试探。注意这是直连目标端口的 QUIC (类 prior-knowledge),
// 不做 Alt-Svc 发现; 目标 UDP 端口取自 URL (默认 443)。

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func newH3Transport(opt *Options, tlsCfg *tls.Config) (*http3.Transport, error) {
	qcfg := &quic.Config{}
	if opt.ConnectTimeout > 0 {
		qcfg.HandshakeIdleTimeout = time.Duration(opt.ConnectTimeout * float64(time.Second))
	} else if !opt.HTTP3Only {
		// 试探模式别让 QUIC 握手超时拖住回落太久
		qcfg.HandshakeIdleTimeout = 3 * time.Second
	}
	tr := &http3.Transport{TLSClientConfig: tlsCfg, QUICConfig: qcfg}
	if opt.IPv4 || opt.IPv6 {
		network := "udp4"
		if opt.IPv6 {
			network = "udp6"
		}
		tr.Dial = func(ctx context.Context, addr string, tc *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			udpAddr, err := net.ResolveUDPAddr(network, addr)
			if err != nil {
				return nil, err
			}
			pc, err := net.ListenPacket(network, ":0")
			if err != nil {
				return nil, err
			}
			return quic.DialEarly(ctx, pc, udpAddr, tc, cfg)
		}
	}
	return tr, nil
}

// protoFallbackTransport: 先试 primary (HTTP/3), 传输失败后用 fallback (TCP) 重发
// 并锁定 fallback。请求体不可重放时 (无 GetBody) 不回落, 直接报 primary 的错误。
type protoFallbackTransport struct {
	primary  http.RoundTripper
	fallback http.RoundTripper

	mu          sync.Mutex
	useFallback bool
}

func (t *protoFallbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	fb := t.useFallback
	t.mu.Unlock()
	if fb {
		return t.fallback.RoundTrip(req)
	}
	resp, err := t.primary.RoundTrip(req)
	if err == nil {
		return resp, nil
	}
	t.mu.Lock()
	t.useFallback = true
	t.mu.Unlock()
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return nil, err
	}
	if req.GetBody != nil {
		body, e := req.GetBody()
		if e != nil {
			return nil, err
		}
		clone := req.Clone(req.Context())
		clone.Body = body
		req = clone
	}
	return t.fallback.RoundTrip(req)
}
