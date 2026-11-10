package main

// HLS 端到端测试: httptest 播放列表与分片服务器, 覆盖媒体列表、主列表选
// 最高码率、AES-128 (显式 IV 与序列号 IV)、BYTERANGE、直播拒绝、清单续传

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func serveBytes(b []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "seg", time.Unix(1700000000, 0), bytes.NewReader(b))
	}
}

func padPKCS7(b []byte) []byte {
	n := aes.BlockSize - len(b)%aes.BlockSize
	out := append([]byte{}, b...)
	for i := 0; i < n; i++ {
		out = append(out, byte(n))
	}
	return out
}

func aesCBCEncrypt(t *testing.T, key, iv, plain []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(padPKCS7(plain)))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padPKCS7(plain))
	return out
}

func TestHLSPlainAndMaster(t *testing.T) {
	segA := bytes.Repeat([]byte("A"), 1000)
	segB := bytes.Repeat([]byte("B"), 2000)
	segC := bytes.Repeat([]byte("C"), 500)
	high := bytes.Repeat([]byte("H"), 777)
	mux := http.NewServeMux()
	mux.HandleFunc("/plain/index.m3u8", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("#EXTM3U\n#EXT-X-TARGETDURATION:10\n#EXTINF:10,\nseg0.ts\n#EXTINF:10,\nseg1.ts\n#EXTINF:10,\nseg2.ts\n#EXT-X-ENDLIST\n"))
	})
	mux.HandleFunc("/plain/seg0.ts", serveBytes(segA))
	mux.HandleFunc("/plain/seg1.ts", serveBytes(segB))
	mux.HandleFunc("/plain/seg2.ts", serveBytes(segC))
	mux.HandleFunc("/master.m3u8", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=100000\nlow/index.m3u8\n#EXT-X-STREAM-INF:BANDWIDTH=900000\nhigh/index.m3u8\n"))
	})
	mux.HandleFunc("/low/index.m3u8", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("#EXTM3U\n#EXTINF:1,\n../plain/seg2.ts\n#EXT-X-ENDLIST\n"))
	})
	mux.HandleFunc("/high/index.m3u8", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("#EXTM3U\n#EXTINF:1,\nh.ts\n#EXT-X-ENDLIST\n"))
	})
	mux.HandleFunc("/high/h.ts", serveBytes(high))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ui := NewUI(true)
	ctx := context.Background()

	dir := t.TempDir()
	if err := DownloadHLS(ctx, srv.URL+"/plain/index.m3u8", &Options{Dir: dir, Split: 2}, dlTask(ui), ui); err != nil {
		t.Fatalf("HLS 下载失败: %v", err)
	}
	want := append(append(append([]byte{}, segA...), segB...), segC...)
	if b, _ := os.ReadFile(filepath.Join(dir, "index.ts")); !bytes.Equal(b, want) {
		t.Fatalf("拼接内容错误: %d 字节, 期望 %d", len(b), len(want))
	}

	dir2 := t.TempDir()
	if err := DownloadHLS(ctx, srv.URL+"/master.m3u8", &Options{Dir: dir2}, dlTask(ui), ui); err != nil {
		t.Fatalf("主列表下载失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir2, "master.ts")); !bytes.Equal(b, high) {
		t.Fatal("主列表应选最高码率变体")
	}
}

// TestRunJobsDispatchHLSMetalink: 主分发按后缀路由 .m3u8 与 .meta4
func TestRunJobsDispatchHLSMetalink(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v/index.m3u8", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("#EXTM3U\n#EXTINF:1,\ns.ts\n#EXT-X-ENDLIST\n"))
	})
	mux.HandleFunc("/v/s.ts", serveBytes([]byte("ts-data")))
	mux.HandleFunc("/m/f.meta4", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="m.bin"><size>7</size><url>` + "http://" + r.Host + `/m/m.bin</url></file></metalink>`))
	})
	mux.HandleFunc("/m/m.bin", serveBytes([]byte("ml-data")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	opt := &Options{Dir: dir, Quiet: true}
	jobs := []job{
		{src: srv.URL + "/v/index.m3u8", opt: opt},
		{src: srv.URL + "/m/f.meta4", opt: opt},
	}
	if err := runJobs(opt, jobs); err != nil {
		t.Fatalf("分发失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "index.ts")); string(b) != "ts-data" {
		t.Fatalf("HLS 分发产物错误: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "m.bin")); string(b) != "ml-data" {
		t.Fatalf("Metalink 分发产物错误: %q", b)
	}
}

func TestHLSEncrypted(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	p0 := bytes.Repeat([]byte("plain-zero-"), 40)
	p1 := bytes.Repeat([]byte("plain-one--"), 40)
	ivExplicit := make([]byte, 16)
	for i := range ivExplicit {
		ivExplicit[i] = byte(i)
	}
	seqIV := func(seq uint64) []byte {
		iv := make([]byte, 16)
		binary.BigEndian.PutUint64(iv[8:], seq)
		return iv
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/key.bin", serveBytes(key))
	// 显式 IV
	mux.HandleFunc("/e1/index.m3u8", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI=\"../key.bin\",IV=0x000102030405060708090a0b0c0d0e0f\n#EXTINF:1,\ns0.ts\n#EXTINF:1,\ns1.ts\n#EXT-X-ENDLIST\n"))
	})
	mux.HandleFunc("/e1/s0.ts", serveBytes(aesCBCEncrypt(t, key, ivExplicit, p0)))
	mux.HandleFunc("/e1/s1.ts", serveBytes(aesCBCEncrypt(t, key, ivExplicit, p1)))
	// 序列号 IV, MEDIA-SEQUENCE=5
	mux.HandleFunc("/e2/index.m3u8", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:5\n#EXT-X-KEY:METHOD=AES-128,URI=\"../key.bin\"\n#EXTINF:1,\ns0.ts\n#EXTINF:1,\ns1.ts\n#EXT-X-ENDLIST\n"))
	})
	mux.HandleFunc("/e2/s0.ts", serveBytes(aesCBCEncrypt(t, key, seqIV(5), p0)))
	mux.HandleFunc("/e2/s1.ts", serveBytes(aesCBCEncrypt(t, key, seqIV(6), p1)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ui := NewUI(true)
	want := append(append([]byte{}, p0...), p1...)
	for _, sub := range []string{"e1", "e2"} {
		dir := t.TempDir()
		if err := DownloadHLS(context.Background(), srv.URL+"/"+sub+"/index.m3u8", &Options{Dir: dir, Split: 2}, dlTask(ui), ui); err != nil {
			t.Fatalf("%s 解密下载失败: %v", sub, err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "index.ts")); !bytes.Equal(b, want) {
			t.Fatalf("%s 解密内容错误", sub)
		}
	}
}

func TestHLSByteRangeAndLiveAndResume(t *testing.T) {
	media := bytes.Repeat([]byte("0123456789"), 300) // 3000 字节单一资源
	var seg2Hits atomic.Int64
	var failSeg2 atomic.Bool
	failSeg2.Store(true)
	mux := http.NewServeMux()
	mux.HandleFunc("/br/index.m3u8", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("#EXTM3U\n#EXT-X-BYTERANGE:1000@0\n#EXTINF:1,\nmedia.ts\n#EXT-X-BYTERANGE:1000\n#EXTINF:1,\nmedia.ts\n#EXT-X-BYTERANGE:1000\n#EXTINF:1,\nmedia.ts\n#EXT-X-ENDLIST\n"))
	})
	mux.HandleFunc("/br/media.ts", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "bytes=2000-2999" {
			seg2Hits.Add(1)
		}
		http.ServeContent(w, r, "media", time.Unix(1700000000, 0), bytes.NewReader(media))
	})
	mux.HandleFunc("/seg/index.m3u8", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("#EXTM3U\n#EXTINF:1,\ns0.ts\n#EXTINF:1,\ns1.ts\n#EXT-X-ENDLIST\n"))
	})
	var s0Hits atomic.Int64
	mux.HandleFunc("/seg/s0.ts", func(w http.ResponseWriter, r *http.Request) {
		s0Hits.Add(1)
		w.Write([]byte("first-"))
	})
	mux.HandleFunc("/seg/s1.ts", func(w http.ResponseWriter, r *http.Request) {
		if failSeg2.Load() {
			time.Sleep(150 * time.Millisecond) // 等第一段先落盘, 保证续传场景确定性
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte("second"))
	})
	mux.HandleFunc("/live.m3u8", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("#EXTM3U\n#EXTINF:1,\nseg/s0.ts\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ui := NewUI(true)
	ctx := context.Background()

	// BYTERANGE (含省略偏移的续接)
	dir := t.TempDir()
	if err := DownloadHLS(ctx, srv.URL+"/br/index.m3u8", &Options{Dir: dir, Split: 3}, dlTask(ui), ui); err != nil {
		t.Fatalf("BYTERANGE 下载失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "index.ts")); !bytes.Equal(b, media) {
		t.Fatal("BYTERANGE 拼接内容错误")
	}
	if seg2Hits.Load() == 0 {
		t.Fatal("第三段应以 bytes=2000-2999 请求")
	}

	// 直播流拒绝
	if err := DownloadHLS(ctx, srv.URL+"/live.m3u8", &Options{Dir: t.TempDir()}, dlTask(ui), ui); err == nil || !strings.Contains(err.Error(), "直播") {
		t.Fatalf("直播应报错, 实际 %v", err)
	}

	// 续传: 第一段成功第二段失败 → 修复后重跑, 第一段不应再取
	dir3 := t.TempDir()
	opt := &Options{Dir: dir3, Split: 2}
	if err := DownloadHLS(ctx, srv.URL+"/seg/index.m3u8", opt, dlTask(ui), ui); err == nil {
		t.Fatal("第二段 500 时应失败")
	}
	failSeg2.Store(false)
	before := s0Hits.Load()
	if err := DownloadHLS(ctx, srv.URL+"/seg/index.m3u8", opt, dlTask(ui), ui); err != nil {
		t.Fatalf("续传失败: %v", err)
	}
	if s0Hits.Load() != before {
		t.Fatal("续传时已完成的第一段不应重新下载")
	}
	if b, _ := os.ReadFile(filepath.Join(dir3, "index.ts")); string(b) != "first-second" {
		t.Fatalf("续传内容错误: %q", b)
	}
}
