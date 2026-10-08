package main

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"net/http"
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
	Size     int64      `json:"size"`
	ETag     string     `json:"etag"`
	Segments []*Segment `json:"segments"`
}

func newHTTPClient(opt *Options) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = 64
	if opt.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if opt.Proxy != "" {
		if u, err := url.Parse(opt.Proxy); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Transport: tr}
}

func newReq(ctx context.Context, method, u string, opt *Options) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", opt.UserAgent)
	for _, h := range opt.Headers {
		if k, v, ok := strings.Cut(h, ":"); ok {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	return req, nil
}

// 探测: 文件大小、是否支持 Range、文件名
func probe(ctx context.Context, c *http.Client, u string, opt *Options) (size int64, ranges bool, name, etag string, err error) {
	req, err := newReq(ctx, http.MethodGet, u, opt)
	if err != nil {
		return
	}
	req.Header.Set("Range", "bytes=0-0")
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
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
	c := newHTTPClient(opt)
	var size int64
	var ranges bool
	var name, etag string
	var err error
	for try := 0; try <= opt.Retries; try++ { // 探测失败 (如 429/5xx) 时指数退避重试
		if size, ranges, name, etag, err = probe(ctx, c, u, opt); err == nil || ctx.Err() != nil {
			break
		}
		select {
		case <-time.After(time.Duration(1<<try) * time.Second):
		case <-ctx.Done():
		}
	}
	if err != nil {
		return err
	}
	if opt.Out != "" {
		name = opt.Out
	}
	task.Name = name
	out := filepath.Join(opt.Dir, name)
	ctlPath := out + ".goria"

	// 已完成的文件直接跳过
	if st, e := os.Stat(out); e == nil && st.Size() == size {
		if _, e := os.Stat(ctlPath); os.IsNotExist(e) {
			ui.Warn("%s 已存在, 跳过", name)
			task.SetTotal(size)
			task.SetDone(size)
			return nil
		}
	}

	ctl := loadControl(ctlPath)
	if ctl == nil || ctl.URL != u || ctl.Size != size || (etag != "" && ctl.ETag != "" && ctl.ETag != etag) {
		ctl = &ControlFile{URL: u, Size: size, ETag: etag, Segments: plan(size, ranges, opt)}
		os.Remove(out)
	}

	fh, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer fh.Close()
	if size > 0 {
		fh.Truncate(size) // 预分配
	}

	var done int64
	for _, s := range ctl.Segments {
		done += s.Done
	}
	task.SetTotal(size)
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
		if size > 0 && s.Start+s.Done > s.End {
			continue
		}
		wg.Add(1)
		go func(s *Segment) {
			defer wg.Done()
			task.SetConns(active.Add(1))
			defer func() { task.SetConns(active.Add(-1)) }()
			var err error
			for try := 0; try <= opt.Retries; try++ {
				if err = fetchSegment(ctx, c, u, opt, fh, s, ranges, task, &mu); err == nil || ctx.Err() != nil {
					break
				}
				time.Sleep(time.Duration(try+1) * time.Second)
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
	if size <= 0 {
		task.SetTotal(task.done.Load())
	}
	os.Remove(ctlPath)

	if opt.Checksum != "" {
		if err := verify(out, opt.Checksum, ui); err != nil {
			return err
		}
	}
	ui.Success("%s", out)
	return nil
}

// 根据文件大小与连接数切分
func plan(size int64, ranges bool, opt *Options) []*Segment {
	if !ranges || size <= 0 || opt.Split <= 1 {
		return []*Segment{{Start: 0, End: size - 1}}
	}
	n := int64(opt.Split)
	if opt.minSplitB > 0 && size/n < opt.minSplitB {
		n = max64(1, size/opt.minSplitB)
	}
	seg := size / n
	var out []*Segment
	for i := int64(0); i < n; i++ {
		s := &Segment{Start: i * seg, End: (i+1)*seg - 1}
		if i == n-1 {
			s.End = size - 1
		}
		out = append(out, s)
	}
	return out
}

func fetchSegment(ctx context.Context, c *http.Client, u string, opt *Options, fh *os.File, s *Segment, ranges bool, task *Task, mu *sync.Mutex) error {
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
			if _, err := fh.WriteAt(buf[:n], off); err != nil {
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

