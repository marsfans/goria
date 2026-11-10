package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dlTask(ui *UI) *Task { return ui.NewTask("test", "HTTP") }

func TestParseRangeSpec(t *testing.T) {
	cases := []struct {
		spec       string
		size       int64
		start, end int64
		wantErr    bool
	}{
		{"0-499", 1000, 0, 499, false},
		{"500-", 1000, 500, 999, false},
		{"-500", 1000, 500, 999, false},
		{"bytes=10-19", 100, 10, 19, false},
		{"0-9999", 100, 0, 99, false},
		{"500-", 0, 500, -1, false},
		{"abc", 100, 0, 0, true},
		{"-10", 0, 0, 0, true},
		{"20-10", 100, 0, 0, true},
		{"", 100, 0, 0, true},
	}
	for _, c := range cases {
		s, e, err := parseRangeSpec(c.spec, c.size)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: 期望报错, 实际 (%d,%d)", c.spec, s, e)
			}
			continue
		}
		if err != nil || s != c.start || e != c.end {
			t.Errorf("%q: 期望 (%d,%d), 实际 (%d,%d) err=%v", c.spec, c.start, c.end, s, e, err)
		}
	}
}

func TestParseTimeCond(t *testing.T) {
	tm, err := parseTimeCond("2024-03-05")
	if err != nil || tm.Year() != 2024 || tm.Month() != 3 || tm.Day() != 5 {
		t.Fatalf("日期解析失败: %v %v", tm, err)
	}
	f := filepath.Join(t.TempDir(), "local.bin")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2023, 5, 4, 3, 2, 1, 0, time.UTC)
	if err := os.Chtimes(f, want, want); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []string{"@" + f, f} {
		got, err := parseTimeCond(spec)
		if err != nil || !got.Equal(want) {
			t.Fatalf("%q: 期望 %v, 实际 %v err=%v", spec, want, got, err)
		}
	}
	if _, err := parseTimeCond("不是日期也不是文件"); err == nil {
		t.Fatal("无效 time-cond 应报错")
	}
}

func TestBuildRequestBodyData(t *testing.T) {
	body, ct, err := buildRequestBody(&Options{Data: []string{"a=1", "b=2"}})
	if err != nil || string(body) != "a=1&b=2" || ct != "application/x-www-form-urlencoded" {
		t.Fatalf("data 拼接错误: %q %q %v", body, ct, err)
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "d.txt")
	os.WriteFile(f, []byte("x=1\r\ny=2\n"), 0o644)
	body, _, err = buildRequestBody(&Options{Data: []string{"@" + f}})
	if err != nil || string(body) != "x=1y=2" {
		t.Fatalf("--data @文件 应去 CR/LF: %q %v", body, err)
	}
	body, _, err = buildRequestBody(&Options{DataBinary: []string{"@" + f}})
	if err != nil || string(body) != "x=1\r\ny=2\n" {
		t.Fatalf("--data-binary @文件 应原样: %q %v", body, err)
	}
	body, _, err = buildRequestBody(&Options{DataRaw: []string{"@x"}})
	if err != nil || string(body) != "@x" {
		t.Fatalf("--data-raw 的 @ 不应特殊处理: %q %v", body, err)
	}
	body, _, err = buildRequestBody(&Options{DataURLEncode: []string{"q=a b&c", "plain", "n=v v"}})
	if err != nil || string(body) != "q=a+b%26c&plain&n=v+v" {
		t.Fatalf("--data-urlencode 错误: %q %v", body, err)
	}
	if _, _, err = buildRequestBody(&Options{Data: []string{"a=1"}, Form: []string{"b=2"}}); err == nil {
		t.Fatal("--data 与 --form 混用应报错")
	}
	body, ct, err = buildRequestBody(&Options{})
	if err != nil || body != nil || ct != "" {
		t.Fatalf("无数据时应返回 nil: %q %q %v", body, ct, err)
	}
}

func TestBuildFormBody(t *testing.T) {
	dir := t.TempDir()
	up := filepath.Join(dir, "up.txt")
	os.WriteFile(up, []byte("hello"), 0o644)
	body, ct, err := buildFormBody([]string{"a=1", "f=@" + up + ";type=text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || mt != "multipart/form-data" {
		t.Fatalf("Content-Type 错误: %q %v", ct, err)
	}
	r := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	got := map[string]string{}
	var fileCT string
	for {
		p, err := r.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(p)
		got[p.FormName()] = string(b)
		if p.FormName() == "f" {
			fileCT = p.Header.Get("Content-Type")
			if p.FileName() != "up.txt" {
				t.Fatalf("文件名错误: %q", p.FileName())
			}
		}
	}
	if got["a"] != "1" || got["f"] != "hello" || fileCT != "text/plain" {
		t.Fatalf("form 解析错误: %v ct=%q", got, fileCT)
	}
}

func TestCookieHeaderValue(t *testing.T) {
	if v, err := cookieHeaderValue(&Options{Cookie: "a=b; c=d"}); err != nil || v != "a=b; c=d" {
		t.Fatalf("字面 cookie 错误: %q %v", v, err)
	}
	f := filepath.Join(t.TempDir(), "cookies.txt")
	os.WriteFile(f, []byte("# Netscape HTTP Cookie File\nexample.com\tFALSE\t/\tFALSE\t0\tsid\tabc123\n"), 0o644)
	if v, err := cookieHeaderValue(&Options{Cookie: f}); err != nil || v != "sid=abc123" {
		t.Fatalf("文件 cookie 错误: %q %v", v, err)
	}
}

func TestValidateOptions(t *testing.T) {
	if err := validateOptions(&Options{}); err != nil {
		t.Fatalf("空选项应合法: %v", err)
	}
	for name, opt := range map[string]*Options{
		"ipv4+ipv6": {IPv4: true, IPv6: true},
		"cert无key":  {Cert: "c.pem"},
		"head+data": {Head: true, Data: []string{"a=1"}},
		"bad-cond":  {TimeCond: "不是日期也不是文件"},
		"bad-range": {Range: "x-y"},
		"neg-time":  {MaxTime: -1},
	} {
		if err := validateOptions(opt); err == nil {
			t.Errorf("%s 应报错", name)
		}
	}
}

func serveContentHandler(content []byte, modtime time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "file.bin", modtime, bytes.NewReader(content))
	}
}

func TestCustomPost(t *testing.T) {
	var gotMethod, gotBody, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotCT = r.Header.Get("Content-Type")
		w.Write([]byte("resp-body"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	opt := &Options{Dir: dir, Out: "out.txt", Data: []string{"a=1", "b=2"}}
	if err := DownloadHTTP(context.Background(), srv.URL+"/submit", opt, dlTask(NewUI(true)), NewUI(true)); err != nil {
		t.Fatal(err)
	}
	if gotMethod != "POST" || gotBody != "a=1&b=2" || gotCT != "application/x-www-form-urlencoded" {
		t.Fatalf("服务端收到: %s %q %q", gotMethod, gotBody, gotCT)
	}
	b, err := os.ReadFile(filepath.Join(dir, "out.txt"))
	if err != nil || string(b) != "resp-body" {
		t.Fatalf("输出文件错误: %q %v", b, err)
	}
}

func TestCustomFormEcho(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Write([]byte("field=" + r.FormValue("name")))
	}))
	defer srv.Close()
	dir := t.TempDir()
	opt := &Options{Dir: dir, Out: "o.txt", Form: []string{"name=goria"}}
	if err := DownloadHTTP(context.Background(), srv.URL, opt, dlTask(NewUI(true)), NewUI(true)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "o.txt"))
	if string(b) != "field=goria" {
		t.Fatalf("form 回显错误: %q", b)
	}
}

func TestCustomFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("errpage"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	ui := NewUI(true)
	opt := &Options{Dir: dir, Out: "a.txt", Data: []string{"x=1"}}
	if err := DownloadHTTP(context.Background(), srv.URL, opt, dlTask(ui), ui); err != nil {
		t.Fatalf("无 --fail 时 500 应保存响应体: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(b) != "errpage" {
		t.Fatalf("响应体未保存: %q", b)
	}
	opt2 := &Options{Dir: dir, Out: "b.txt", Data: []string{"x=1"}, Fail: true}
	if err := DownloadHTTP(context.Background(), srv.URL, opt2, dlTask(ui), ui); err == nil {
		t.Fatal("--fail 时 500 应报错")
	}
	if _, err := os.Stat(filepath.Join(dir, "b.txt")); !os.IsNotExist(err) {
		t.Fatal("--fail 时不应落盘")
	}
}

func TestCustomIncludeAndGzip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Mark", "yes")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			gz.Write([]byte("zipped-body"))
			gz.Close()
			return
		}
		w.Write([]byte("plain-body"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	ui := NewUI(true)
	opt := &Options{Dir: dir, Out: "inc.txt", Include: true}
	if err := DownloadHTTP(context.Background(), srv.URL, opt, dlTask(ui), ui); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "inc.txt"))
	// 传输层默认自动请求 gzip, 该 handler 见 gzip 就回 zipped-body 并被透明解压, 故正文是 zipped-body
	if !strings.HasPrefix(string(b), "HTTP/1.1 200 OK") || !strings.Contains(string(b), "X-Mark: yes") || !strings.HasSuffix(string(b), "zipped-body") {
		t.Fatalf("--include 输出错误: %q", b)
	}
	opt2 := &Options{Dir: dir, Out: "gz.txt", Data: []string{"x=1"}, Compressed: true}
	if err := DownloadHTTP(context.Background(), srv.URL, opt2, dlTask(ui), ui); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "gz.txt")); string(b) != "zipped-body" {
		t.Fatalf("--compressed 应解压后再落盘: %q", b)
	}
}

func TestHeadMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			http.Error(w, "want HEAD", 405)
			return
		}
		w.Header().Set("X-Test", "abc")
		w.Write([]byte("hello"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	dump := filepath.Join(t.TempDir(), "hdr.txt")
	opt := &Options{Dir: dir, Head: true, DumpHeader: dump}
	if err := DownloadHTTP(context.Background(), srv.URL+"/file.bin", opt, dlTask(NewUI(true)), NewUI(true)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dump)
	if err != nil || !strings.Contains(string(b), "X-Test: abc") {
		t.Fatalf("dump-header 错误: %q %v", b, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("-I 不应下载文件, 目录里有 %v", entries)
	}
}

func TestRangeAndHeaders(t *testing.T) {
	content := []byte("abcdefghijklmnopqrstuvwxyz")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Referer") != "https://ref.example/" ||
			r.Header.Get("Cookie") != "sid=42" {
			http.Error(w, "missing headers", 403)
			return
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "alice" || p != "secret" {
			http.Error(w, "missing auth", 401)
			return
		}
		http.ServeContent(w, r, "file.bin", time.Now(), bytes.NewReader(content))
	}))
	defer srv.Close()
	dir := t.TempDir()
	ui := NewUI(true)
	opt := &Options{Dir: dir, Range: "2-5", Referer: "https://ref.example/", Cookie: "sid=42", User: "alice:secret"}
	if err := DownloadHTTP(context.Background(), srv.URL+"/file.bin", opt, dlTask(ui), ui); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "file.bin")); string(b) != "cdef" {
		t.Fatalf("--range 2-5 应得到 cdef, 实际 %q", b)
	}
	opt2 := &Options{Dir: dir, Out: "suffix.txt", Range: "-4", Referer: "https://ref.example/", Cookie: "sid=42", User: "alice:secret"}
	if err := DownloadHTTP(context.Background(), srv.URL+"/file.bin", opt2, dlTask(ui), ui); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "suffix.txt")); string(b) != "wxyz" {
		t.Fatalf("--range -4 应得到 wxyz, 实际 %q", b)
	}
}

func TestContinueAt(t *testing.T) {
	content := []byte("0123456789ABCDEFGHIJ")
	srv := httptest.NewServer(serveContentHandler(content, time.Now()))
	defer srv.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.bin"), content[:6], 0o644); err != nil {
		t.Fatal(err)
	}
	opt := &Options{Dir: dir, ContinueAt: "6"}
	if err := DownloadHTTP(context.Background(), srv.URL+"/file.bin", opt, dlTask(NewUI(true)), NewUI(true)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "file.bin")); !bytes.Equal(b, content) {
		t.Fatalf("-C 6 续传结果错误: %q", b)
	}
}

func TestTimeCondNotModified(t *testing.T) {
	content := []byte("some content")
	mod := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(serveContentHandler(content, mod))
	defer srv.Close()
	dir := t.TempDir()
	opt := &Options{Dir: dir, TimeCond: "2025-01-01"}
	if err := DownloadHTTP(context.Background(), srv.URL+"/file.bin", opt, dlTask(NewUI(true)), NewUI(true)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "file.bin")); !os.IsNotExist(err) {
		t.Fatal("304 时不应创建文件")
	}
}

func TestRedirectControl(t *testing.T) {
	content := []byte("target-content")
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	mux.HandleFunc("/target", serveContentHandler(content, time.Now()))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ui := NewUI(true)
	dir := t.TempDir()
	opt := &Options{Dir: dir, NoLocation: true}
	if err := DownloadHTTP(context.Background(), srv.URL+"/start", opt, dlTask(ui), ui); err == nil {
		t.Fatal("--no-location 遇 302 应失败")
	}
	dir2 := t.TempDir()
	opt2 := &Options{Dir: dir2, MaxRedirs: -1}
	if err := DownloadHTTP(context.Background(), srv.URL+"/start", opt2, dlTask(ui), ui); err != nil {
		t.Fatalf("默认应跟随重定向: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir2, "target")); string(b) != string(content) {
		t.Fatalf("重定向后内容错误: %q", b)
	}
	opt3 := &Options{Dir: t.TempDir(), MaxRedirs: 0}
	if err := DownloadHTTP(context.Background(), srv.URL+"/start", opt3, dlTask(ui), ui); err == nil {
		t.Fatal("--max-redirs 0 应拦住重定向")
	}
}

func TestCookieJarAndIPv4(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "xyz", Path: "/"})
		w.Write([]byte("body"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	jar := filepath.Join(dir, "jar.txt")
	opt := &Options{Dir: dir, CookieJar: jar, IPv4: true}
	if err := DownloadHTTP(context.Background(), srv.URL+"/f.txt", opt, dlTask(NewUI(true)), NewUI(true)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(jar)
	if err != nil || !strings.Contains(string(b), "session") || !strings.Contains(string(b), "xyz") {
		t.Fatalf("cookie-jar 错误: %q %v", b, err)
	}
}
