package main

// curl 兼容层: 参数名与功能借鉴 curl, 但定位仍是下载器。
// 与 aria2 命名冲突的短名保持原义 (见 main.go Options 注释), 只提供长名:
// --data (短 -d 是 dir)、--proxy (短 -x 是 split)、--max-time (短 -m 是 max-tries)、
// --include (短 -i 是 input-file)。不冲突的短名与 curl 一致: -A -e -b -c -u -4 -6
// -L -f -C -r -z -O -J -I -D -v -s -S -X -F -Z。
// 单连接请求路径: 带请求体/非 GET 方法/--include 的任务无法分片与断点续传,
// 走这里的一次性请求; 普通 GET 下载仍走 http.go 的分片引擎。

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var errNotModified = errors.New("服务器内容未修改 (304)")

// isCustomRequest 判断任务是否必须走单连接请求路径
func isCustomRequest(opt *Options) bool {
	if len(opt.Data) > 0 || len(opt.DataBinary) > 0 || len(opt.DataRaw) > 0 ||
		len(opt.DataURLEncode) > 0 || len(opt.Form) > 0 || opt.Include {
		return true
	}
	m := strings.ToUpper(strings.TrimSpace(opt.Method))
	return m != "" && m != "GET" && m != "HEAD"
}

func validateOptions(opt *Options) error {
	if opt.IPv4 && opt.IPv6 {
		return fmt.Errorf("-4/--ipv4 与 -6/--ipv6 不能同时使用")
	}
	if (opt.Cert == "") != (opt.Key == "") {
		return fmt.Errorf("--cert 与 --key 须成对提供")
	}
	if opt.Head && (len(opt.Data) > 0 || len(opt.DataBinary) > 0 || len(opt.DataRaw) > 0 ||
		len(opt.DataURLEncode) > 0 || len(opt.Form) > 0) {
		return fmt.Errorf("-I/--head 不能与 --data/--form 同时使用")
	}
	if opt.TimeCond != "" {
		if _, err := parseTimeCond(opt.TimeCond); err != nil {
			return err
		}
	}
	if opt.Range != "" {
		if _, _, err := parseRangeSpec(opt.Range, 0); err != nil {
			return err
		}
	}
	if opt.ContinueAt != "" && opt.ContinueAt != "-" {
		if _, err := parseSize(opt.ContinueAt); err != nil {
			return fmt.Errorf("--continue-at 无效: %w", err)
		}
	}
	if opt.ConnectTimeout < 0 || opt.MaxTime < 0 || opt.RetryDelay < 0 {
		return fmt.Errorf("--connect-timeout/--max-time/--retry-delay 不能为负")
	}
	return nil
}

// parseTimeCond 解析 curl -z 的时间条件: 日期字符串, 或 @文件 / 文件路径 (取修改时间)
func parseTimeCond(spec string) (time.Time, error) {
	s := strings.TrimSpace(spec)
	if strings.HasPrefix(s, "@") {
		return fileMTime(s[1:])
	}
	layouts := []string{
		http.TimeFormat, time.RFC1123, time.RFC1123Z, time.RFC3339,
		"2006-01-02 15:04:05", "2006-01-02", time.RFC850, time.RubyDate, time.ANSIC,
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), nil
		}
	}
	if _, err := os.Stat(s); err == nil {
		return fileMTime(s)
	}
	return time.Time{}, fmt.Errorf("--time-cond 无法解析 %q (支持日期如 2024-01-02 / RFC3339, 或 @文件取修改时间)", spec)
}

func fileMTime(p string) (time.Time, error) {
	st, err := os.Stat(p)
	if err != nil {
		return time.Time{}, fmt.Errorf("--time-cond 文件 %q: %w", p, err)
	}
	return st.ModTime().UTC(), nil
}

// parseRangeSpec 解析 curl -r 的区间: "0-499" / "500-" / "-500" (后缀长度)。
// size<=0 表示大小未知: 开区间后缀暂记为 start<0 的哨兵不允许出现 —— 后缀式必须知道大小,
// size 未知时返回错误; 开尾式 end 记为 -1 由调用方在知道大小后收敛。
func parseRangeSpec(spec string, size int64) (start, end int64, err error) {
	s := strings.TrimSpace(spec)
	s = strings.TrimPrefix(s, "bytes=")
	lo, hi, ok := strings.Cut(s, "-")
	if !ok || (lo == "" && hi == "") {
		return 0, 0, fmt.Errorf("--range 格式应为 起-止 / 起- / -后缀长度, 实际 %q", spec)
	}
	parse := func(x string) (int64, error) {
		n, e := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		if e != nil || n < 0 {
			return 0, fmt.Errorf("--range 无效数字 %q", x)
		}
		return n, nil
	}
	if lo == "" { // 后缀式: 最后 n 字节
		n, e := parse(hi)
		if e != nil {
			return 0, 0, e
		}
		if size <= 0 {
			return 0, 0, fmt.Errorf("--range 后缀式 %q 需要先知道文件大小", spec)
		}
		if n > size {
			n = size
		}
		return size - n, size - 1, nil
	}
	start, err = parse(lo)
	if err != nil {
		return 0, 0, err
	}
	if hi == "" {
		if size > 0 {
			return start, size - 1, nil
		}
		return start, -1, nil
	}
	end, err = parse(hi)
	if err != nil {
		return 0, 0, err
	}
	if end < start {
		return 0, 0, fmt.Errorf("--range 结束 %d 小于开始 %d", end, start)
	}
	if size > 0 && end > size-1 {
		end = size - 1
	}
	return start, end, nil
}

// cookieHeaderValue 解析 -b: 含 "=" 视为字面 Cookie 值; 否则若是已存在文件,
// 按 Netscape cookie 文件格式解析为 Cookie 头
func cookieHeaderValue(opt *Options) (string, error) {
	v := strings.TrimSpace(opt.Cookie)
	if v == "" || strings.Contains(v, "=") {
		return v, nil
	}
	b, err := os.ReadFile(v)
	if err != nil {
		return v, nil // 不是文件就按字面值用 (可能是不带 = 的单值 cookie)
	}
	var pairs []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		line = strings.TrimPrefix(line, "#HttpOnly_")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) >= 7 {
			pairs = append(pairs, f[5]+"="+f[6])
		}
	}
	if len(pairs) == 0 {
		return "", fmt.Errorf("--cookie 文件 %q 里没有 Netscape 格式的 cookie", v)
	}
	return strings.Join(pairs, "; "), nil
}

// dumpCookies 把 client 的 cookie jar 中属于该 URL 的 cookie 以 Netscape 格式写出 (curl -c)
func dumpCookies(c *http.Client, rawurl, jarPath string) error {
	if c.Jar == nil {
		return nil
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# Netscape HTTP Cookie File\n# generated by goria\n")
	for _, ck := range c.Jar.Cookies(u) {
		domain := ck.Domain
		if domain == "" {
			domain = u.Hostname()
		}
		exp := int64(0)
		if !ck.Expires.IsZero() {
			exp = ck.Expires.Unix()
		}
		fmt.Fprintf(&b, "%s\tFALSE\t%s\t%s\t%d\t%s\t%s\n",
			domain, ck.Path, strconv.FormatBool(ck.Secure), exp, ck.Name, ck.Value)
	}
	if dir := filepath.Dir(jarPath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(jarPath, []byte(b.String()), 0o644)
}

// headerDumpText 把响应状态行与响应头格式化为 curl -D/-i 的文本形态
func headerDumpText(resp *http.Response) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\r\n", resp.Proto, resp.Status)
	resp.Header.Write(&b)
	b.WriteString("\r\n")
	return b.String()
}

func writeDumpHeader(opt *Options, resp *http.Response, ui *UI) {
	if opt.DumpHeader == "" {
		return
	}
	text := headerDumpText(resp)
	if opt.DumpHeader == "-" {
		fmt.Fprint(os.Stderr, text)
		return
	}
	if err := os.WriteFile(opt.DumpHeader, []byte(text), 0o644); err != nil {
		ui.Warn("写 dump-header 失败: %v", err)
	}
}

// verboseLog 输出一条 curl -v 风格的日志行, 敏感头脱敏
func verboseLog(ui *UI, opt *Options, format string, a ...any) {
	if opt.Verbose {
		ui.Info(format, a...)
	}
}

func verboseHeaders(ui *UI, opt *Options, dir string, h http.Header) {
	if !opt.Verbose {
		return
	}
	for k, vs := range h {
		for _, v := range vs {
			if k == "Authorization" || k == "Cookie" {
				v = "***"
			}
			ui.Info("%s %s: %s", dir, k, v)
		}
	}
}

// buildRequestBody 组装 --data 家族 / --form 的请求体, 返回 body 与 Content-Type。
// 多个 --data 类分段按 curl 规则以 & 连接; --form 与 --data 不能混用 (curl 同)。
func buildRequestBody(opt *Options) ([]byte, string, error) {
	if len(opt.Form) > 0 {
		if len(opt.Data) > 0 || len(opt.DataBinary) > 0 || len(opt.DataRaw) > 0 || len(opt.DataURLEncode) > 0 {
			return nil, "", fmt.Errorf("--form 不能与 --data 家族同时使用")
		}
		return buildFormBody(opt.Form)
	}
	var parts [][]byte
	appendData := func(specs []string, mode int) error {
		for _, s := range specs {
			var part []byte
			switch mode {
			case dataURL:
				v, err := urlEncodeDataPart(s)
				if err != nil {
					return err
				}
				part = []byte(v)
			case dataRaw:
				part = []byte(s)
			default: // data / dataBinary: @文件
				if strings.HasPrefix(s, "@") {
					b, err := os.ReadFile(s[1:])
					if err != nil {
						return fmt.Errorf("读取数据文件 %q: %w", s[1:], err)
					}
					if mode == dataPlain { // curl --data 读文件会去掉所有 CR/LF
						b = bytes.ReplaceAll(bytes.ReplaceAll(b, []byte("\r"), nil), []byte("\n"), nil)
					}
					part = b
				} else {
					part = []byte(s)
				}
			}
			parts = append(parts, part)
		}
		return nil
	}
	if err := appendData(opt.Data, dataPlain); err != nil {
		return nil, "", err
	}
	if err := appendData(opt.DataRaw, dataRaw); err != nil {
		return nil, "", err
	}
	if err := appendData(opt.DataBinary, dataBinary); err != nil {
		return nil, "", err
	}
	if err := appendData(opt.DataURLEncode, dataURL); err != nil {
		return nil, "", err
	}
	if len(parts) == 0 {
		return nil, "", nil
	}
	return bytes.Join(parts, []byte("&")), "application/x-www-form-urlencoded", nil
}

const (
	dataPlain = iota
	dataBinary
	dataRaw
	dataURL
)

// urlEncodeDataPart 实现 curl --data-urlencode 的四种形态
func urlEncodeDataPart(s string) (string, error) {
	esc := url.QueryEscape
	if strings.HasPrefix(s, "@") { // @文件: 整体编码文件内容
		b, err := os.ReadFile(s[1:])
		if err != nil {
			return "", fmt.Errorf("读取数据文件 %q: %w", s[1:], err)
		}
		return esc(string(b)), nil
	}
	if name, rest, ok := strings.Cut(s, "@"); ok && name != "" && !strings.Contains(name, "=") {
		// name@文件
		b, err := os.ReadFile(rest)
		if err != nil {
			return "", fmt.Errorf("读取数据文件 %q: %w", rest, err)
		}
		return name + "=" + esc(string(b)), nil
	}
	if name, content, ok := strings.Cut(s, "="); ok { // name=content: 只编码 content
		return name + "=" + esc(content), nil
	}
	return esc(s), nil
}

// buildFormBody 组装 multipart/form-data (curl -F)
func buildFormBody(specs []string) ([]byte, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, s := range specs {
		name, val, ok := strings.Cut(s, "=")
		if !ok || name == "" {
			return nil, "", fmt.Errorf("--form 格式应为 name=value 或 name=@文件, 实际 %q", s)
		}
		switch {
		case strings.HasPrefix(val, "@"): // 文件上传, 可带 ;type= / ;filename=
			rest := val[1:]
			file, params, _ := strings.Cut(rest, ";")
			hdr := make(textproto.MIMEHeader)
			fname := filepath.Base(file)
			ctype := ""
			for _, p := range strings.Split(params, ";") {
				if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok {
					switch k {
					case "filename":
						fname = v
					case "type":
						ctype = v
					}
				}
			}
			if ctype == "" {
				ctype = mime.TypeByExtension(filepath.Ext(fname))
			}
			if ctype == "" {
				ctype = "application/octet-stream"
			}
			hdr.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, name, fname))
			hdr.Set("Content-Type", ctype)
			w, err := mw.CreatePart(hdr)
			if err != nil {
				return nil, "", err
			}
			b, err := os.ReadFile(file)
			if err != nil {
				return nil, "", fmt.Errorf("--form 读取文件 %q: %w", file, err)
			}
			if _, err := w.Write(b); err != nil {
				return nil, "", err
			}
		case strings.HasPrefix(val, "<"): // 字段值取自文件内容
			b, err := os.ReadFile(val[1:])
			if err != nil {
				return nil, "", fmt.Errorf("--form 读取文件 %q: %w", val[1:], err)
			}
			if err := mw.WriteField(name, string(b)); err != nil {
				return nil, "", err
			}
		default:
			if err := mw.WriteField(name, val); err != nil {
				return nil, "", err
			}
		}
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), mw.FormDataContentType(), nil
}

func outPath(opt *Options, name string) (string, error) {
	out := filepath.Join(opt.Dir, name)
	if opt.CreateDirs {
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return "", err
		}
	}
	return out, nil
}

func hasContentTypeHeader(opt *Options) bool {
	for _, h := range opt.Headers {
		if k, _, ok := strings.Cut(h, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Content-Type") {
			return true
		}
	}
	return false
}

// doHead 实现 curl -I: 只发 HEAD, 输出响应头 (到 --dump-header 文件, 或 stdout)
func doHead(ctx context.Context, c *http.Client, u string, opt *Options, task *Task, ui *UI) error {
	var resp *http.Response
	var err error
	for try := 0; try <= opt.Retries; try++ {
		var req *http.Request
		req, err = newReq(ctx, http.MethodHead, u, opt)
		if err != nil {
			return err
		}
		verboseLog(ui, opt, "> HEAD %s", u)
		resp, err = c.Do(req)
		if err == nil || ctx.Err() != nil {
			break
		}
		select {
		case <-time.After(opt.retryDelay(try)):
		case <-ctx.Done():
		}
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	verboseLog(ui, opt, "< %s", resp.Status)
	verboseHeaders(ui, opt, "<", resp.Header)
	if opt.Fail && resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %s (--fail)", resp.Status)
	}
	task.SetTotal(0)
	if opt.DumpHeader != "" {
		writeDumpHeader(opt, resp, ui)
	} else {
		fmt.Fprint(os.Stdout, headerDumpText(resp))
	}
	if opt.CookieJar != "" {
		if err := dumpCookies(c, u, opt.CookieJar); err != nil {
			ui.Warn("保存 cookie-jar 失败: %v", err)
		}
	}
	ui.Success("%s HEAD %s", u, resp.Status)
	return nil
}

// doCustomRequest 单连接请求路径 (curl -X/--data/-F/--include):
// 不分片、不写控制文件、不可断点续传; 状态码默认按 curl 语义保存响应体,
// --fail 时 >=400 报错且不落盘。传输错误按 --max-tries 重试 (每次重发完整请求体)。
func doCustomRequest(ctx context.Context, c *http.Client, u string, opt *Options, task *Task, ui *UI) error {
	body, ctype, err := buildRequestBody(opt)
	if err != nil {
		return err
	}
	method := strings.ToUpper(strings.TrimSpace(opt.Method))
	if method == "" {
		if body != nil {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
	}
	name := opt.Out
	if name == "" {
		name = path.Base(strings.SplitN(u, "?", 2)[0])
		if name == "" || name == "/" || name == "." {
			name = "index.html"
		}
	}
	task.Name = name
	out, err := outPath(opt, name)
	if err != nil {
		return err
	}

	var resp *http.Response
	for try := 0; try <= opt.Retries; try++ {
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		var req *http.Request
		req, err = newReqBody(ctx, method, u, opt, rdr)
		if err != nil {
			return err
		}
		if body != nil {
			req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
			req.ContentLength = int64(len(body))
			if ctype != "" && !hasContentTypeHeader(opt) {
				req.Header.Set("Content-Type", ctype)
			}
		}
		if opt.Range != "" { // 单连接下 -r 直接转成 Range 头
			rng := opt.Range
			if !strings.HasPrefix(rng, "bytes=") {
				rng = "bytes=" + rng
			}
			req.Header.Set("Range", rng)
		}
		if opt.TimeCond != "" {
			t, e := parseTimeCond(opt.TimeCond)
			if e != nil {
				return e
			}
			req.Header.Set("If-Modified-Since", t.Format(http.TimeFormat))
		}
		if opt.Compressed { // 显式请求 gzip 并在下面手动解压 (传输层不会替显式头解压)
			req.Header.Set("Accept-Encoding", "gzip")
		}
		verboseLog(ui, opt, "> %s %s", method, u)
		verboseHeaders(ui, opt, ">", req.Header)
		resp, err = c.Do(req)
		if err == nil || ctx.Err() != nil {
			break
		}
		select {
		case <-time.After(opt.retryDelay(try)):
		case <-ctx.Done():
		}
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	verboseLog(ui, opt, "< %s", resp.Status)
	verboseHeaders(ui, opt, "<", resp.Header)
	writeDumpHeader(opt, resp, ui)

	if resp.StatusCode == http.StatusNotModified {
		ui.Info("%s 未修改 (304), 跳过", name)
		task.SetTotal(0)
		return nil
	}
	if opt.Fail && resp.StatusCode >= 400 {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("HTTP %s (--fail)", resp.Status)
	}
	var src io.Reader = resp.Body
	gzipped := opt.Compressed && strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip")
	if gzipped {
		gz, e := gzip.NewReader(resp.Body)
		if e != nil {
			return fmt.Errorf("解压 gzip 响应失败: %w", e)
		}
		defer gz.Close()
		src = gz
	} else if resp.ContentLength >= 0 {
		task.SetTotal(resp.ContentLength)
	}
	fh, err := os.Create(out)
	if err != nil {
		return err
	}
	defer fh.Close()
	if opt.Include { // curl -i: 响应头写在响应体之前
		if _, err := fh.WriteString(headerDumpText(resp)); err != nil {
			return err
		}
	}
	if err := copyWithLimiter(ctx, fh, src, opt, task); err != nil {
		return err
	}
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

// copyWithLimiter 按全局限速把响应体写入文件并更新任务进度
func copyWithLimiter(ctx context.Context, dst io.Writer, src io.Reader, opt *Options, task *Task) error {
	buf := make([]byte, 64*1024)
	for {
		if opt.limiter != nil {
			if err := opt.limiter.WaitN(ctx, len(buf)); err != nil {
				return err
			}
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				return err
			}
			task.Add(int64(n))
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}
