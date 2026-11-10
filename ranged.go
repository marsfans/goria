package main

// 非 HTTP 协议 (FTP/SFTP) 共用的分片下载引擎: 与 DownloadHTTP 相同的控制文件
// (.goria) 续传语义、进度汇总、重试与校验, 只有取数方式由 fetch 回调提供。
// fetch 从 s.Start+s.Done 处取本段剩余字节, 经 pumpSegment 写文件;
// validator 是远端文件的版本标识 (修改时间), 存入控制文件的 ETag 字段比对。

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type segFetchFunc func(ctx context.Context, fh *os.File, s *Segment, mu *sync.Mutex) error

// pumpSegment 把 r 的字节写进 fh 的段内偏移处, 同步更新 s.Done 与任务进度;
// 已知段尾 (s.End >= 0) 时提前 EOF 视为错误, 未知大小时 EOF 即完成
func pumpSegment(ctx context.Context, r io.Reader, fh *os.File, opt *Options, s *Segment, task *Task, mu *sync.Mutex) error {
	mu.Lock()
	off := s.Start + s.Done
	mu.Unlock()
	var want int64 = -1
	if s.End >= 0 {
		want = s.End - off + 1
	}
	buf := make([]byte, 64*1024)
	var got int64
	for want < 0 || got < want {
		if opt.limiter != nil {
			if err := opt.limiter.WaitN(ctx, len(buf)); err != nil {
				return err
			}
		}
		n, rerr := r.Read(buf)
		if n > 0 {
			// 数据源可能越过段尾多给 (如 FTP 的 RETR 发到文件尾):
			// 只取本段应得的, 多余部分归下一段自己取, 保证 Done 计数精确
			if want >= 0 && int64(n) > want-got {
				n = int(want - got)
			}
			if _, err := fh.WriteAt(buf[:n], off); err != nil {
				return err
			}
			off += int64(n)
			got += int64(n)
			mu.Lock()
			s.Done += int64(n)
			mu.Unlock()
			task.Add(int64(n))
		}
		if rerr == io.EOF {
			if want >= 0 && got < want {
				return errors.New("连接提前关闭")
			}
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
	return nil
}

func runSegmentedDownload(ctx context.Context, rawurl, name string, size int64, validator string, opt *Options, task *Task, ui *UI, fetch segFetchFunc) error {
	task.Name = name
	out, err := outPath(opt, name)
	if err != nil {
		return err
	}
	ctlPath := out + ".goria"

	if st, e := os.Stat(out); e == nil && size > 0 && st.Size() == size {
		if _, e := os.Stat(ctlPath); os.IsNotExist(e) {
			ui.Warn("%s 已存在, 跳过", name)
			task.SetTotal(size)
			task.SetDone(size)
			return nil
		}
	}

	ctl := loadControl(ctlPath)
	fresh := ctl == nil || ctl.URL != rawurl || ctl.Size != size ||
		(validator != "" && ctl.ETag != "" && ctl.ETag != validator)
	if fresh {
		ctl = &ControlFile{URL: rawurl, Size: size, ETag: validator, Segments: plan(size, true, opt)}
		os.Remove(out)
	}

	fh, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer fh.Close()
	if size > 0 {
		fh.Truncate(size)
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
				if err = fetch(ctx, fh, s, &mu); err == nil || ctx.Err() != nil {
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
