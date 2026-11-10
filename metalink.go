package main

// Metalink 下载: 解析 .metalink (v3) 与 .meta4 (RFC 6249) 两种 XML 格式
// (标签按本地名匹配, 命名空间通吃), 每个文件走多镜像 HTTP 引擎下载:
// probe 逐个镜像试、段级按段轮换并故障转移。下载后按 <pieces> 做分片
// 哈希校验, 坏片从其它镜像定点重取修复, 最后做整文件哈希校验。

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
)

type mlHashXML struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type mlPiecesXML struct {
	Type   string   `xml:"type,attr"`
	Length int64    `xml:"length,attr"`
	Hashes []string `xml:"hash"`
}

type mlURLXML struct {
	Type       string `xml:"type,attr"`
	Preference int    `xml:"preference,attr"`
	Priority   int    `xml:"priority,attr"`
	Value      string `xml:",chardata"`
}

type mlFileXML struct {
	Name    string       `xml:"name,attr"`
	Size    int64        `xml:"size"`
	HashesV []mlHashXML  `xml:"verification>hash"`
	HashesD []mlHashXML  `xml:"hash"`
	PiecesV *mlPiecesXML `xml:"verification>pieces"`
	PiecesD *mlPiecesXML `xml:"pieces"`
	URLsRes []mlURLXML   `xml:"resources>url"`
	URLsDir []mlURLXML   `xml:"url"`
}

type mlRootXML struct {
	FilesWrapped []mlFileXML `xml:"files>file"`
	FilesDirect  []mlFileXML `xml:"file"`
}

type mlFile struct {
	Name    string
	Size    int64
	Hash    string // verify() 用的 "algo=hex" 形式, 空 = 无整文件哈希
	Pieces  *mlPiecesXML
	Mirrors []string // 已排序的 http(s) 镜像, 第一个是主源
}

func mlNormAlgo(t string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(t)), "-", "")
}

func mlHashOf(algo string, r io.Reader) (string, error) {
	var h hash.Hash
	switch mlNormAlgo(algo) {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	default:
		return "", fmt.Errorf("不支持的哈希算法: %s", algo)
	}
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func parseMetalink(data []byte) ([]mlFile, error) {
	var root mlRootXML
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("解析 Metalink 失败: %w", err)
	}
	raw := append(append([]mlFileXML{}, root.FilesWrapped...), root.FilesDirect...)
	var out []mlFile
	for _, rf := range raw {
		if strings.TrimSpace(rf.Name) == "" {
			continue
		}
		f := mlFile{Name: rf.Name, Size: rf.Size, Pieces: rf.PiecesV}
		if f.Pieces == nil {
			f.Pieces = rf.PiecesD
		}
		// 整文件哈希: sha256 优先, 其次 sha1、md5
		hashes := append(append([]mlHashXML{}, rf.HashesV...), rf.HashesD...)
		best := -1
		for _, h := range hashes {
			pri := map[string]int{"sha256": 3, "sha1": 2, "md5": 1}[mlNormAlgo(h.Type)]
			if pri > best {
				best = pri
				f.Hash = mlNormAlgo(h.Type) + "=" + strings.ToLower(strings.TrimSpace(h.Value))
			}
		}
		if best < 0 {
			f.Hash = ""
		}
		urls := append(append([]mlURLXML{}, rf.URLsRes...), rf.URLsDir...)
		var httpURLs []mlURLXML
		for _, u := range urls {
			v := strings.TrimSpace(u.Value)
			if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
				httpURLs = append(httpURLs, u)
			}
		}
		hasPriority := false
		for _, u := range httpURLs {
			if u.Priority > 0 {
				hasPriority = true
			}
		}
		sort.SliceStable(httpURLs, func(i, j int) bool {
			if hasPriority { // meta4: priority 越小越优先, 0 视为最低
				pi, pj := httpURLs[i].Priority, httpURLs[j].Priority
				if pi == 0 {
					pi = 1 << 30
				}
				if pj == 0 {
					pj = 1 << 30
				}
				return pi < pj
			}
			return httpURLs[i].Preference > httpURLs[j].Preference // v3: preference 越大越优先
		})
		for _, u := range httpURLs {
			f.Mirrors = append(f.Mirrors, strings.TrimSpace(u.Value))
		}
		if len(f.Mirrors) == 0 {
			return nil, fmt.Errorf("Metalink 文件 %s 没有可用的 http(s) 镜像", rf.Name)
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("Metalink 中没有文件条目")
	}
	return out, nil
}

// verifyMLPieces 校验分片哈希并从镜像定点修复坏片
func verifyMLPieces(ctx context.Context, c *http.Client, out string, f mlFile, opt *Options, ui *UI) error {
	p := f.Pieces
	if p == nil || p.Length <= 0 || len(p.Hashes) == 0 {
		return nil
	}
	algo := mlNormAlgo(p.Type)
	check := func() ([]int, error) {
		fh, err := os.Open(out)
		if err != nil {
			return nil, err
		}
		defer fh.Close()
		st, err := fh.Stat()
		if err != nil {
			return nil, err
		}
		var bad []int
		for i, want := range p.Hashes {
			off := int64(i) * p.Length
			if off >= st.Size() {
				break
			}
			end := min(off+p.Length, st.Size())
			got, err := mlHashOf(algo, io.NewSectionReader(fh, off, end-off))
			if err != nil {
				return nil, err
			}
			if !strings.EqualFold(got, strings.TrimSpace(want)) {
				bad = append(bad, i)
			}
		}
		return bad, nil
	}
	bad, err := check()
	if err != nil {
		return err
	}
	for _, idx := range bad {
		off := int64(idx) * p.Length
		ln := p.Length
		if f.Size > 0 && off+ln > f.Size {
			ln = f.Size - off
		}
		repaired := false
		for _, m := range f.Mirrors {
			data, _, err := fetchHLSBytes(ctx, c, m, opt, &hlsByteRange{Off: off, Len: ln})
			if err != nil || int64(len(data)) != ln {
				continue
			}
			got, err := mlHashOf(algo, strings.NewReader(string(data)))
			if err != nil || !strings.EqualFold(got, strings.TrimSpace(p.Hashes[idx])) {
				continue // 这个镜像的这一片也是坏的, 换下一个
			}
			fh, err := os.OpenFile(out, os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			if _, err := fh.WriteAt(data, off); err != nil {
				fh.Close()
				return err
			}
			fh.Close()
			repaired = true
			ui.Info("分片 %d 校验失败, 已从镜像 %s 修复", idx, m)
			break
		}
		if !repaired {
			return fmt.Errorf("分片 %d 哈希校验失败, 且所有镜像都无法提供正确数据", idx)
		}
	}
	return nil
}

func DownloadMetalink(ctx context.Context, src string, opt *Options, task *Task, ui *UI) error {
	var data []byte
	var err error
	if strings.Contains(src, "://") {
		c, err2 := newHTTPClient(opt)
		if err2 != nil {
			return err2
		}
		if data, _, err = fetchHLSBytes(ctx, c, src, opt, nil); err != nil {
			return err
		}
	} else {
		if data, err = os.ReadFile(src); err != nil {
			return err
		}
	}
	files, err := parseMetalink(data)
	if err != nil {
		return err
	}
	c, err := newHTTPClient(opt)
	if err != nil {
		return err
	}
	for _, f := range files {
		fo := *opt
		// 文件名强制收敛到保存目录内, 防御 ../ 与绝对路径
		fo.Out = path.Clean("/" + f.Name)[1:]
		fo.Checksum = "" // 校验推迟到分片修复之后
		if len(f.Mirrors) > 1 {
			fo.mirrors = f.Mirrors[1:]
		} else {
			fo.mirrors = nil
		}
		task.Name = fo.Out
		if err := DownloadHTTP(ctx, f.Mirrors[0], &fo, task, ui); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		out, err := outPath(&fo, fo.Out)
		if err != nil {
			return err
		}
		if err := verifyMLPieces(ctx, c, out, f, &fo, ui); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		if f.Hash != "" {
			if err := verify(out, f.Hash, ui); err != nil {
				return fmt.Errorf("%s: %w", f.Name, err)
			}
		}
	}
	return nil
}
