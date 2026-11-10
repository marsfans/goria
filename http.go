package main

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 控制文件 (类似 aria2 的 .aria2), 用于断点续传
type Segment struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"` // 含
	Done  int64 `json:"done"`
}

type ControlFile struct {
	URL      string     `json:"url"`
	Size     int64      `json:"size"`           // 本次要下载的字节数 (--range 时为区间长度)
	Base     int64      `json:"base,omitempty"` // --range 的起始偏移, 文件内写入需减去它
	ETag     string     `json:"etag"`
	Segments []*Segment `json:"segments"`
}

func newHTTPClient(opt *Options) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = 64
	// --compressed: 下载路径的分片请求带 Range, 传输层本就不会对 Range 请求加 gzip;
	// 无 Range 的单连接请求由传输层透明解压, 这里只须确保未禁用压缩。
	tr.DisableCompression = false

	dialer := &net.Dialer{KeepAlive: 30 * time.Second}
	if opt.ConnectTimeout > 0 {
		d := time.Duration(opt.ConnectTimeout * float64(time.Second))
		dialer.Timeout = d
		tr.TLSHandshakeTimeout = d
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if opt.IPv4 {
			network = "tcp4"
		} else if opt.IPv6 {
			network = "tcp6"
		}
		return dialer.DialContext(ctx, network, addr)
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: opt.Insecure}
	needTLS := opt.Insecure
	if opt.CACert != "" {
		pem, err := os.ReadFile(opt.CACert)
		if err != nil {
			return nil, fmt.Errorf("--cacert: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--cacert: %q 中没有可用的 PEM 证书", opt.CACert)
		}
		tlsCfg.RootCAs = pool
		needTLS = true
	}
	if opt.Cert != "" && opt.Key != "" {
		cert, err := tls.LoadX509KeyPair(opt.Cert, opt.Key)
		if err != nil {
			return nil, fmt.Errorf("--cert/--key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
		needTLS = true
	}
	if needTLS {
		tr.TLSClientConfig = tlsCfg
	}
	if opt.Proxy != "" {
		u, err := url.Parse(opt.Proxy)
		if err != nil {
			return nil, fmt.Errorf("代理地址无效: %w", err)
		}
		tr.Proxy = http.ProxyURL(u)
	}
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Transport: tr,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if opt.NoLocation {
				return http.ErrUseLastResponse
			}
			limit := 10 // Go 默认
			if opt.MaxRedirs >= 0 {
				limit = opt.MaxRedirs
			}
			if len(via) > limit {
				return fmt.Errorf("重定向次数超过上限 %d (--max-redirs)", limit)
			}
			return nil
		},
	}, nil
}

func newReq(ctx context.Context, method, u string, opt *Options) (*http.Request, error) {
	return newReqBody(ctx, method, u, opt, nil)
}

func newReqBody(ctx context.Context, method, u string, opt *Options, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", opt.UserAgent)
	for _, h := range opt.Headers {
		if k, v, ok := strings.Cut(h, ":"); ok {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	// curl 兼容头 (专用参数优先于同名 -H 的情况不做处理: 后设置的覆盖先设置的)
	if opt.Referer != "" {
		req.Header.Set("Referer", strings.TrimSuffix(opt.Referer, ";auto"))
	}
	if opt.Cookie != "" {
		cv, err := cookieHeaderValue(opt)
		if err != nil {
			return nil, err
		}
		if cv != "" {
			req.Header.Set("Cookie", cv)
		}
	}
	if opt.User != "" {
		user, pass, _ := strings.Cut(opt.User, ":")
		req.SetBasicAuth(user, pass)
	}
	return req, nil
}

// 探测: 文件大小、是否支持 Range、文件名; 同时带回响应头与状态行供 -D 使用
func probe(ctx context.Context, c *http.Client, u string, opt *Options) (size int64, ranges bool, name, etag string, hdr http.Header, status string, err error) {
	req, err := newReq(ctx, http.MethodGet, u, opt)
	if err != nil {
		return
	}
	req.Header.Set("Range", "bytes=0-0")
	if opt.TimeCond != "" {
		var t time.Time
		t, err = parseTimeCond(opt.TimeCond)
		if err != nil {
			return
		}
		req.Header.Set("If-Modified-Since", t.Format(http.TimeFormat))
	}
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	hdr, status = resp.Header, resp.Status
	if resp.StatusCode == http.StatusNotModified {
		err = errNotModified
		return
	}
	switch resp.StatusCode {
	case http.StatusPartialContent:
		ranges = true
		// Content-Range: bytes 0-0/12345
		if cr := resp.Header.Get("Content-Range"); cr != "" {
			if i := strings.LastIndex(cr, "/"); i >= 0 {
				fmt.Sscanf(cr[i+1:], "%d", &size)
			}
		}
	case http.StatusOK:
		size = resp.ContentLength
	default:
		err = fmt.Errorf("HTTP %s", resp.Status)
		return
	}
	etag = resp.Header.Get("ETag")
	if _, p, e := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); e == nil && p["filename"] != "" {
		name = filepath.Base(p["filename"])
	}
	if name == "" {
		name = path.Base(resp.Request.URL.Path) // 跟随重定向后的路径
		if n, e := url.PathUnescape(name); e == nil {
			name = n
		}
	}
	if name == "" || name == "/" || name == "." {
		name = "index.html"
	}
	return
}

func DownloadHTTP(ctx context.Context, u string, opt *Options, task *Task, ui *UI) error {
	o := *opt // 每任务一份副本: --range 解析结果等任务内状态不与其他并发任务共享
	opt = &o
	c, err := newHTTPClient(opt)
	if err != nil {
		return err
	}
	// curl -I 与单连接请求路径分流 (见 curl.go)
	if opt.Head {
		return doHead(ctx, c, u, opt, task, ui)
	}
	if isCustomRequest(opt) {
		return doCustomRequest(ctx, c, u, opt, task, ui)
	}

	var size int64
	var ranges bool
	var name, etag string
	var hdr http.Header
	var status string
	for try := 0; try <= opt.Retries; try++ { // 探测失败 (如 429/5xx) 时重试
		if size, ranges, name, etag, hdr, status, err = probe(ctx, c, u, opt); err == nil || err == errNotModified || ctx.Err() != nil {
			break
		}
		select {
		case <-time.After(opt.retryDelay(try)):
		case <-ctx.Done():
		}
	}
	if err == errNotModified {
		ui.Info("%s 未修改 (304), 跳过", displayName(u))
		task.SetTotal(0)
		return nil
	}
	if err != nil {
		return err
	}
	verboseLog(ui, opt, "> GET %s -> %s", u, status)
	if opt.DumpHeader != "" { // 下载路径下 -D 保存探测响应的头
		writeDumpHeader(opt, &http.Response{Proto: "HTTP/1.1", Status: status, Header: hdr}, ui)
	}
	if opt.Out != "" {
		name = opt.Out
	}
	task.Name = name
	out, err := outPath(opt, name)
	if err != nil {
		return err
	}
	ctlPath := out + ".goria"

	// --range: 把有效下载区间收敛为 [rangeBase, rangeEnd], dlSize 为区间长度
	dlSize := size
	opt.rangeBase, opt.rangeEnd = 0, -1
	if opt.Range == "" {
		// 未重传 --range 时, 若已有同 URL 的区间下载控制文件, 按其 Base/Size 恢复区间
		if pre := loadControl(ctlPath); pre != nil && pre.URL == u && pre.Base != 0 && pre.Size > 0 &&
			!(etag != "" && pre.ETag != "" && pre.ETag != etag) {
			opt.rangeBase, dlSize = pre.Base, pre.Size
		}
	}
	if opt.Range != "" {
		if !ranges {
			return fmt.Errorf("服务器不支持 Range, 无法使用 --range")
		}
		var rs, re int64
		if rs, re, err = parseRangeSpec(opt.Range, size); err != nil {
			return err
		}
		if size > 0 && rs >= size {
			return fmt.Errorf("--range 起始 %d 超出文件大小 %d", rs, size)
		}
		opt.rangeBase, opt.rangeEnd = rs, re
		dlSize = re - rs + 1
	}
	// -C 偏移续传: 仅在没有控制文件时生效, 要求本地已有文件承载前 offset 字节
	var continueOffset int64
	if opt.ContinueAt != "" && opt.ContinueAt != "-" {
		if continueOffset, err = parseSize(opt.ContinueAt); err != nil {
			return err
		}
	}

	// 已完成的文件直接跳过
	if st, e := os.Stat(out); e == nil && st.Size() == dlSize && dlSize > 0 {
		if _, e := os.Stat(ctlPath); os.IsNotExist(e) {
			ui.Warn("%s 已存在, 跳过", name)
			task.SetTotal(dlSize)
			task.SetDone(dlSize)
			return nil
		}
	}

	ctl := loadControl(ctlPath)
	fresh := ctl == nil || ctl.URL != u || ctl.Size != dlSize || ctl.Base != opt.rangeBase ||
		(etag != "" && ctl.ETag != "" && ctl.ETag != etag)
	if fresh {
		ctl = &ControlFile{URL: u, Size: dlSize, Base: opt.rangeBase, ETag: etag, Segments: plan(dlSize, ranges, opt)}
		if continueOffset > 0 {
			st, e := os.Stat(out)
			if e != nil || st.Size() < continueOffset {
				return fmt.Errorf("--continue-at %d: 本地文件 %s 不存在或不足该偏移, 无法续传", continueOffset, out)
			}
			if !ranges {
				return fmt.Errorf("--continue-at 需要服务器支持 Range")
			}
			if continueOffset >= dlSize {
				return fmt.Errorf("--continue-at %d 不小于待下载大小 %d", continueOffset, dlSize)
			}
			ctl.Segments = []*Segment{{Start: opt.rangeBase, End: opt.rangeBase + dlSize - 1, Done: continueOffset}}
		} else {
			os.Remove(out)
		}
	}

	fh, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer fh.Close()
	if dlSize > 0 {
		fh.Truncate(dlSize) // 预分配 (续传时保留已有前缀)
	}

	var done int64
	for _, s := range ctl.Segments {
		done += s.Done
	}
	task.SetTotal(dlSize)
	task.SetDone(done)
	if done > 0 {
		ui.Info("%s 断点续传, 从 %s 继续", name, humanBytes(float64(done)))
	}
	var active atomic.Int64

	var mu sync.Mutex
	save := func() {
		mu.Lock()
		defer mu.Unlock()
		b, _ := json.Marshal(ctl)
		os.WriteFile(ctlPath, b, 0o644)
	}

	// 定期保存进度
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				save()
			case <-stop:
				return
			}
		}
	}()

	var wg sync.WaitGroup
	errCh := make(chan error, len(ctl.Segments))
	for _, s := range ctl.Segments {
		if dlSize > 0 && s.Start+s.Done > s.End {
			continue
		}
		wg.Add(1)
		go func(s *Segment) {
			defer wg.Done()
			task.SetConns(active.Add(1))
			defer func() { task.SetConns(active.Add(-1)) }()
			var err error
			for try := 0; try <= opt.Retries; try++ {
				if err = fetchSegment(ctx, c, u, opt, fh, s, ranges, task, ui, &mu); err == nil || ctx.Err() != nil {
					break
				}
				time.Sleep(opt.retryDelay(try))
			}
			if err != nil {
				errCh <- err
			}
		}(s)
	}
	wg.Wait()
	close(stop)
	close(errCh)

	if err := <-errCh; err != nil || ctx.Err() != nil {
		save()
		if err == nil {
			err = ctx.Err()
		}
		return err
	}
	if dlSize <= 0 {
		task.SetTotal(task.done.Load())
	}
	os.Remove(ctlPath)

	if opt.CookieJar != "" {
		if err := dumpCookies(c, u, opt.CookieJar); err != nil {
			ui.Warn("保存 cookie-jar 失败: %v", err)
		}
	}
	if opt.Checksum != "" {
		if err := verify(out, opt.Checksum, ui); err != nil {
			return err
		}
	}
	ui.Success("%s", out)
	return nil
}

// 根据文件大小与连接数切分; dlSize 为有效下载长度, 段偏移以 opt.rangeBase 为起点
func plan(dlSize int64, ranges bool, opt *Options) []*Segment {
	base := opt.rangeBase
	if opt.Range != "" {
		return []*Segment{{Start: base, End: base + dlSize - 1}}
	}
	if !ranges || dlSize <= 0 || opt.Split <= 1 {
		return []*Segment{{Start: 0, End: dlSize - 1}}
	}
	n := int64(opt.Split)
	if opt.minSplitB > 0 && dlSize/n < opt.minSplitB {
		n = max64(1, dlSize/opt.minSplitB)
	}
	seg := dlSize / n
	var out []*Segment
	for i := int64(0); i < n; i++ {
		s := &Segment{Start: i * seg, End: (i+1)*seg - 1}
		if i == n-1 {
			s.End = dlSize - 1
		}
		out = append(out, s)
	}
	return out
}

func fetchSegment(ctx context.Context, c *http.Client, u string, opt *Options, fh *os.File, s *Segment, ranges bool, task *Task, ui *UI, mu *sync.Mutex) error {
	req, err := newReq(ctx, http.MethodGet, u, opt)
	if err != nil {
		return err
	}
	mu.Lock()
	off := s.Start + s.Done
	mu.Unlock()
	if ranges {
		if s.End >= 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, s.End))
		} else {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", off))
		}
	} else if off > 0 {
		// 不支持 Range 的服务器只能从头开始
		mu.Lock()
		task.Add(-s.Done)
		s.Done, off = 0, 0
		mu.Unlock()
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	verboseLog(ui, opt, "< %s (段 %d-%d)", resp.Status, s.Start, s.End)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	buf := make([]byte, 64*1024)
	for {
		if opt.limiter != nil {
			if err := opt.limiter.WaitN(ctx, len(buf)); err != nil {
				return err
			}
		}
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := fh.WriteAt(buf[:n], off-opt.rangeBase); err != nil {
				return err
			}
			off += int64(n)
			mu.Lock()
			s.Done += int64(n)
			mu.Unlock()
			task.Add(int64(n))
		}
		if rerr == io.EOF {
			if s.End >= 0 && off <= s.End {
				return errors.New("连接提前关闭")
			}
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

func loadControl(p string) *ControlFile {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var c ControlFile
	if json.Unmarshal(b, &c) != nil {
		return nil
	}
	return &c
}

func verify(file, spec string, ui *UI) error {
	algo, want, ok := strings.Cut(spec, "=")
	if !ok {
		return fmt.Errorf("checksum 格式应为 算法=值")
	}
	var h hash.Hash
	switch strings.ToLower(strings.ReplaceAll(algo, "-", "")) {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	default:
		return fmt.Errorf("不支持的校验算法 %s", algo)
	}
	fh, err := os.Open(file)
	if err != nil {
		return err
	}
	defer fh.Close()
	io.Copy(h, fh)
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, want) {
		return fmt.Errorf("校验失败: 期望 %s, 实际 %s", want, got)
	}
	ui.Success("校验通过 %s", filepath.Base(file))
	return nil
}
