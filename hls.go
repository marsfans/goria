package main

// HLS (m3u8) 下载: 解析主/媒体播放列表, 并发拉取分片后按序拼接为单个文件。
// 支持主列表选最高码率、EXT-X-KEY AES-128 (显式 IV 或媒体序列号 IV)、
// EXT-X-BYTERANGE、EXT-X-MAP 初始化段。仅点播 (须有 EXT-X-ENDLIST), 直播报错。
// 分片存 <out>.hls-parts/, 清单 <out>.hls.json 记录完成状态, 中断后可续传。
// 分片与密钥请求走 goria 的 HTTP 客户端, 代理/TLS/Header/Cookie 设置照常生效。

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type hlsByteRange struct {
	Off int64 `json:"off"`
	Len int64 `json:"len"`
}

type hlsKeyRef struct {
	URI string // 相对媒体列表的密钥地址, 空 = 不加密
	IV  []byte // 显式 IV, nil = 用媒体序列号
}

type hlsSeg struct {
	URL       string        `json:"url"`
	ByteRange *hlsByteRange `json:"br,omitempty"`
	KeyURI    string        `json:"key,omitempty"`
	KeyIV     []byte        `json:"iv,omitempty"`
	Seq       int64         `json:"seq"`
	Done      bool          `json:"done"`
	Size      int64         `json:"size"`
}

type hlsManifest struct {
	Playlist string   `json:"playlist"` // 媒体列表最终 URL, 变了则清单作废
	Segs     []hlsSeg `json:"segs"`
}

// parseHLSAttrs 解析 KEY=VALUE,... 属性串 (值可带引号, 引号内可含逗号)
func parseHLSAttrs(s string) map[string]string {
	out := map[string]string{}
	var parts []string
	var cur strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			cur.WriteRune(r)
		case r == ',' && !inQ:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	parts = append(parts, cur.String())
	for _, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), "\"")
	}
	return out
}

func parseHLSRange(s string) *hlsByteRange {
	ln, off, found := strings.Cut(s, "@")
	l, err := strconv.ParseInt(strings.TrimSpace(ln), 10, 64)
	if err != nil {
		return nil
	}
	o := int64(-1)
	if found {
		o, _ = strconv.ParseInt(strings.TrimSpace(off), 10, 64)
	}
	return &hlsByteRange{Off: o, Len: l}
}

// parseHLSMaster 从主列表挑最高码率的变体地址 (无码率信息取第一个)
func parseHLSMaster(body string, base *url.URL) (string, error) {
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	bestBW := int64(-1)
	var best string
	var pendingBW int64 = -1
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "#EXT-X-STREAM-INF:") {
			pendingBW = -1
			if bw, err := strconv.ParseInt(parseHLSAttrs(strings.TrimPrefix(ln, "#EXT-X-STREAM-INF:"))["BANDWIDTH"], 10, 64); err == nil {
				pendingBW = bw
			}
			continue
		}
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if ref, err := url.Parse(ln); err == nil {
			u := ln
			if base != nil {
				u = base.ResolveReference(ref).String()
			}
			if pendingBW > bestBW || best == "" {
				bestBW, best = pendingBW, u
			}
		}
		pendingBW = -1
	}
	if best == "" {
		return "", fmt.Errorf("主播放列表中没有可用变体")
	}
	return best, nil
}

// parseHLSMedia 解析媒体列表; live=true 表示没有 EXT-X-ENDLIST
func parseHLSMedia(body string, base *url.URL) (segs []hlsSeg, live bool, err error) {
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	var mediaSeq int64
	var key *hlsKeyRef
	var pendingBR *hlsByteRange
	lastEnd := map[string]int64{}
	resolve := func(s string) string {
		if base == nil {
			return s
		}
		if ref, e := url.Parse(s); e == nil {
			return base.ResolveReference(ref).String()
		}
		return s
	}
	endlist := false
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(ln, "#EXT-X-MEDIA-SEQUENCE:"):
			mediaSeq, _ = strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(ln, "#EXT-X-MEDIA-SEQUENCE:")), 10, 64)
		case strings.HasPrefix(ln, "#EXT-X-KEY:"):
			attrs := parseHLSAttrs(strings.TrimPrefix(ln, "#EXT-X-KEY:"))
			if attrs["METHOD"] == "" || attrs["METHOD"] == "NONE" {
				key = nil
			} else if attrs["METHOD"] == "AES-128" {
				k := &hlsKeyRef{URI: resolve(attrs["URI"])}
				if ivHex := attrs["IV"]; ivHex != "" {
					if b, e := hex.DecodeString(strings.TrimPrefix(ivHex, "0x")); e == nil && len(b) == 16 {
						k.IV = b
					}
				}
				key = k
			} else {
				return nil, false, fmt.Errorf("不支持的 HLS 加密方式: %s", attrs["METHOD"])
			}
		case strings.HasPrefix(ln, "#EXT-X-BYTERANGE:"):
			pendingBR = parseHLSRange(strings.TrimPrefix(ln, "#EXT-X-BYTERANGE:"))
		case strings.HasPrefix(ln, "#EXT-X-MAP:"):
			attrs := parseHLSAttrs(strings.TrimPrefix(ln, "#EXT-X-MAP:"))
			seg := hlsSeg{URL: resolve(attrs["URI"]), Seq: mediaSeq}
			if br := attrs["BYTERANGE"]; br != "" {
				seg.ByteRange = parseHLSRange(br)
			}
			if key != nil {
				seg.KeyURI, seg.KeyIV = key.URI, key.IV
			}
			segs = append(segs, seg)
		case ln == "#EXT-X-ENDLIST":
			endlist = true
		case ln == "" || strings.HasPrefix(ln, "#"):
			// EXTINF 等其余标签不影响取数
		default:
			seg := hlsSeg{URL: resolve(ln), Seq: mediaSeq + int64(len(segs))}
			if pendingBR != nil {
				br := *pendingBR
				if br.Off < 0 {
					br.Off = lastEnd[seg.URL]
				}
				lastEnd[seg.URL] = br.Off + br.Len
				seg.ByteRange = &br
				pendingBR = nil
			}
			if key != nil {
				seg.KeyURI, seg.KeyIV = key.URI, key.IV
			}
			segs = append(segs, seg)
		}
	}
	if len(segs) == 0 {
		return nil, false, fmt.Errorf("播放列表中没有分片")
	}
	return segs, !endlist, nil
}

func decryptHLSSegment(data, key, iv []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("AES-128 密钥长度应为 16 字节, 实际 %d", len(key))
	}
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("加密分片长度 %d 不是块大小的倍数", len(data))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	pad := int(out[len(out)-1])
	if pad < 1 || pad > aes.BlockSize {
		return nil, fmt.Errorf("PKCS#7 填充无效")
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("PKCS#7 填充无效")
		}
	}
	return out[:len(out)-pad], nil
}

// fetchHLSBytes 用 goria 的客户端取一段字节 (播放列表/密钥/分片共用)
func fetchHLSBytes(ctx context.Context, c *http.Client, u string, opt *Options, br *hlsByteRange) ([]byte, string, error) {
	req, err := newReq(ctx, http.MethodGet, u, opt)
	if err != nil {
		return nil, "", err
	}
	if br != nil {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", br.Off, br.Off+br.Len-1))
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, "", fmt.Errorf("HTTP %s (%s)", resp.Status, u)
	}
	var buf bytes.Buffer
	chunk := make([]byte, 64*1024)
	for {
		if opt.limiter != nil {
			if err := opt.limiter.WaitN(ctx, len(chunk)); err != nil {
				return nil, "", err
			}
		}
		n, rerr := resp.Body.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, "", rerr
		}
	}
	final := u
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return buf.Bytes(), final, nil
}

func DownloadHLS(ctx context.Context, src string, opt *Options, task *Task, ui *UI) error {
	o := *opt
	opt = &o
	if opt.Range != "" || opt.ContinueAt != "" {
		return fmt.Errorf("--range/--continue-at 仅适用于普通 HTTP 下载")
	}
	c, err := newHTTPClient(opt)
	if err != nil {
		return err
	}
	isLocal := !strings.Contains(src, "://")
	var body []byte
	mediaURL := src
	if isLocal {
		if body, err = os.ReadFile(src); err != nil {
			return err
		}
	} else {
		var final string
		if body, final, err = fetchHLSBytes(ctx, c, src, opt, nil); err != nil {
			return err
		}
		mediaURL = final
	}
	srcURL := mediaURL // 输出文件名按用户给的地址 (主列表) 派生, 不用变体地址
	base, _ := url.Parse(mediaURL)
	if strings.Contains(string(body), "#EXT-X-STREAM-INF") {
		variant, err := parseHLSMaster(string(body), base)
		if err != nil {
			return err
		}
		if body, mediaURL, err = fetchHLSBytes(ctx, c, variant, opt, nil); err != nil {
			return err
		}
		base, _ = url.Parse(mediaURL)
	}
	segs, live, err := parseHLSMedia(string(body), base)
	if err != nil {
		return err
	}
	if live {
		return fmt.Errorf("HLS 直播流 (无 EXT-X-ENDLIST) 暂不支持")
	}

	name := opt.Out
	if name == "" {
		srcBase, _ := url.Parse(srcURL)
		name = path.Base(srcBase.Path)
		name = strings.TrimSuffix(name, ".m3u8") + ".ts"
		if name == ".ts" || name == "" {
			name = "stream.ts"
		}
	}
	task.Name = name
	out, err := outPath(opt, name)
	if err != nil {
		return err
	}
	partsDir := out + ".hls-parts"
	manifestPath := out + ".hls.json"
	if err := os.MkdirAll(partsDir, 0o755); err != nil {
		return err
	}

	// 续传: 清单与本次列表逐项一致才复用完成状态
	man := &hlsManifest{Playlist: mediaURL, Segs: segs}
	if b, e := os.ReadFile(manifestPath); e == nil {
		var old hlsManifest
		if json.Unmarshal(b, &old) == nil && old.Playlist == mediaURL && len(old.Segs) == len(segs) {
			same := true
			for i := range segs {
				if old.Segs[i].URL != segs[i].URL {
					same = false
					break
				}
			}
			if same {
				man = &old
			}
		}
	}
	var mu sync.Mutex
	saveManifest := func() {
		mu.Lock()
		defer mu.Unlock()
		b, _ := json.Marshal(man)
		os.WriteFile(manifestPath, b, 0o644)
	}
	var resumed int
	var doneBytes int64
	for i := range man.Segs {
		if man.Segs[i].Done {
			if st, e := os.Stat(filepath.Join(partsDir, fmt.Sprintf("%06d", i))); e == nil && st.Size() == man.Segs[i].Size {
				resumed++
				doneBytes += man.Segs[i].Size
				continue
			}
			man.Segs[i].Done = false
		}
	}
	task.SetTotal(0)
	task.Add(doneBytes)
	if resumed > 0 {
		ui.Info("%s HLS 续传: %d/%d 个分片已就绪", name, resumed, len(segs))
	}

	keys := map[string][]byte{}
	var keyMu sync.Mutex
	getKey := func(uri string) ([]byte, error) {
		keyMu.Lock()
		defer keyMu.Unlock()
		if k, ok := keys[uri]; ok {
			return k, nil
		}
		k, _, err := fetchHLSBytes(ctx, c, uri, opt, nil)
		if err != nil {
			return nil, fmt.Errorf("取 HLS 密钥失败: %w", err)
		}
		keys[uri] = k
		return k, nil
	}

	workers := max(1, opt.Split)
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var active atomic.Int64
	errCh := make(chan error, len(segs))
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for i := range man.Segs {
		if man.Segs[i].Done {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-dctx.Done():
				return
			}
			task.SetConns(active.Add(1))
			defer func() { task.SetConns(active.Add(-1)) }()
			seg := &man.Segs[i]
			var data []byte
			var err error
			for try := 0; try <= opt.Retries; try++ {
				if data, _, err = fetchHLSBytes(dctx, c, seg.URL, opt, seg.ByteRange); err == nil {
					break
				}
				if dctx.Err() != nil {
					return
				}
			}
			if err != nil {
				errCh <- fmt.Errorf("分片 %d: %w", i, err)
				cancel()
				return
			}
			if seg.KeyURI != "" {
				key, err := getKey(seg.KeyURI)
				if err != nil {
					errCh <- err
					cancel()
					return
				}
				iv := seg.KeyIV
				if iv == nil {
					iv = make([]byte, 16)
					binary.BigEndian.PutUint64(iv[8:], uint64(seg.Seq))
				}
				if data, err = decryptHLSSegment(data, key, iv); err != nil {
					errCh <- fmt.Errorf("分片 %d 解密失败: %w", i, err)
					cancel()
					return
				}
			}
			part := filepath.Join(partsDir, fmt.Sprintf("%06d", i))
			if err := os.WriteFile(part, data, 0o644); err != nil {
				errCh <- err
				cancel()
				return
			}
			mu.Lock()
			seg.Done = true
			seg.Size = int64(len(data))
			mu.Unlock()
			saveManifest()
			task.Add(int64(len(data)))
		}(i)
	}
	wg.Wait()
	close(errCh)
	if err := <-errCh; err != nil {
		saveManifest()
		return err
	}
	if ctx.Err() != nil {
		saveManifest()
		return ctx.Err()
	}

	// 按序拼接
	fh, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	for i := range man.Segs {
		part, err := os.Open(filepath.Join(partsDir, fmt.Sprintf("%06d", i)))
		if err != nil {
			fh.Close()
			return err
		}
		_, err = io.Copy(fh, part)
		part.Close()
		if err != nil {
			fh.Close()
			return err
		}
	}
	fh.Close()
	os.RemoveAll(partsDir)
	os.Remove(manifestPath)
	task.SetTotal(task.done.Load())
	if opt.Checksum != "" {
		if err := verify(out, opt.Checksum, ui); err != nil {
			return err
		}
	}
	ui.Success("%s (%d 个分片)", out, len(segs))
	return nil
}
