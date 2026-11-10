package main

// Metalink 端到端测试: v3 (.metalink 本地文件) 与 meta4 (.meta4 URL) 双格式、
// 死镜像 probe 故障转移、分片哈希坏片从好镜像定点修复

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func pieceHashes(content []byte, plen int) []string {
	var out []string
	for off := 0; off < len(content); off += plen {
		end := min(off+plen, len(content))
		out = append(out, fmt.Sprintf("%x", sha256.Sum256(content[off:end])))
	}
	return out
}

func contentServer(content []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "f.bin", time.Unix(1700000000, 0), bytes.NewReader(content))
	}))
}

func TestMetalinkMeta4Failover(t *testing.T) {
	content := bytes.Repeat([]byte("metalink-content"), 16384) // 256 KiB
	plen := 65536
	hashes := pieceHashes(content, plen)
	whole := fmt.Sprintf("%x", sha256.Sum256(content))
	var sb strings.Builder
	for _, h := range hashes {
		sb.WriteString("<hash>" + h + "</hash>")
	}
	good := contentServer(content)
	defer good.Close()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer dead.Close()
	meta := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<metalink xmlns="urn:ietf:params:xml:ns:metalink">
  <file name="f.bin">
    <size>%d</size>
    <hash type="sha-256">%s</hash>
    <pieces type="sha-256" length="%d">%s</pieces>
    <url priority="1">%s/f.bin</url>
    <url priority="2">%s/f.bin</url>
  </file>
</metalink>`, len(content), whole, plen, sb.String(), dead.URL, good.URL)
	metaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(meta))
	}))
	defer metaSrv.Close()

	dir := t.TempDir()
	ui := NewUI(true)
	opt := &Options{Dir: dir, Split: 4}
	if err := DownloadMetalink(context.Background(), metaSrv.URL+"/f.meta4", opt, dlTask(ui), ui); err != nil {
		t.Fatalf("meta4 下载失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "f.bin")); !bytes.Equal(b, content) {
		t.Fatal("meta4 下载内容不一致 (死镜像应被跳过)")
	}
}

func TestMetalinkV3LocalAndPieceRepair(t *testing.T) {
	content := bytes.Repeat([]byte("repair-me-please"), 16384) // 256 KiB
	plen := 65536
	hashes := pieceHashes(content, plen)
	whole := fmt.Sprintf("%x", sha256.Sum256(content))

	// 坏镜像: 第 1 片 (65536..131071) 的字节被翻转
	corrupt := append([]byte{}, content...)
	for i := plen; i < 2*plen; i++ {
		corrupt[i] ^= 0xFF
	}
	badSrv := contentServer(corrupt)
	defer badSrv.Close()
	var goodRangeHits atomic.Int64
	goodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == fmt.Sprintf("bytes=%d-%d", plen, 2*plen-1) {
			goodRangeHits.Add(1)
		}
		http.ServeContent(w, r, "f.bin", time.Unix(1700000000, 0), bytes.NewReader(content))
	}))
	defer goodSrv.Close()

	var piecesXML strings.Builder
	for _, h := range hashes {
		piecesXML.WriteString("<hash>" + h + "</hash>")
	}
	meta := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<metalink version="3.0" xmlns="http://www.metalinker.org/">
  <files>
    <file name="f.bin">
      <size>%d</size>
      <verification>
        <hash type="sha256">%s</hash>
        <pieces type="sha256" length="%d">%s</pieces>
      </verification>
      <resources>
        <url type="http" preference="200">%s/f.bin</url>
        <url type="http" preference="100">%s/f.bin</url>
      </resources>
    </file>
  </files>
</metalink>`, len(content), whole, plen, piecesXML.String(), badSrv.URL, goodSrv.URL)
	metaPath := filepath.Join(t.TempDir(), "f.metalink")
	os.WriteFile(metaPath, []byte(meta), 0o644)

	dir := t.TempDir()
	ui := NewUI(true)
	// Split=1: 整文件只从排第一的坏镜像下, 坏片必然出现, 修复只能靠好镜像
	opt := &Options{Dir: dir, Split: 1}
	if err := DownloadMetalink(context.Background(), metaPath, opt, dlTask(ui), ui); err != nil {
		t.Fatalf("v3 下载/修复失败: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "f.bin")); !bytes.Equal(b, content) {
		t.Fatal("坏片修复后内容仍不一致")
	}
	if goodRangeHits.Load() != 1 {
		t.Fatalf("好镜像应恰好收到 1 次坏片定点请求, 实际 %d", goodRangeHits.Load())
	}
}

func TestParseMetalinkFormats(t *testing.T) {
	files, err := parseMetalink([]byte(`<metalink xmlns="urn:ietf:params:xml:ns:metalink">
  <file name="a.bin"><size>10</size>
    <hash type="sha-256">AB12</hash>
    <url priority="2">https://b.example/a.bin</url>
    <url priority="1">https://a.example/a.bin</url>
    <url>ftp://ftp.example/a.bin</url>
  </file></metalink>`))
	if err != nil || len(files) != 1 {
		t.Fatalf("meta4 解析失败: %v", err)
	}
	f := files[0]
	if f.Hash != "sha256=ab12" {
		t.Fatalf("哈希归一化错误: %s", f.Hash)
	}
	if len(f.Mirrors) != 2 || f.Mirrors[0] != "https://a.example/a.bin" {
		t.Fatalf("镜像应按 priority 升序且剔除 ftp: %v", f.Mirrors)
	}
	if _, err := parseMetalink([]byte(`<metalink><files></files></metalink>`)); err == nil {
		t.Fatal("空 metalink 应报错")
	}
}
