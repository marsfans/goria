package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
)

type BTClient struct {
	c   *torrent.Client
	opt *Options
}

func NewBTClient(opt *Options) (*BTClient, error) {
	cfg := torrent.NewDefaultClientConfig()
	cfg.DataDir = opt.Dir
	cfg.ListenPort = opt.BTListen
	cfg.Seed = opt.SeedRatio > 0
	c, err := torrent.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &BTClient{c: c, opt: opt}, nil
}

func (b *BTClient) Close() { b.c.Close() }

func (b *BTClient) Download(ctx context.Context, src string, task *Task, ui *UI) error {
	var t *torrent.Torrent
	var err error
	if strings.HasPrefix(src, "magnet:") {
		t, err = b.c.AddMagnet(src)
	} else {
		var mi *metainfo.MetaInfo
		if mi, err = metainfo.LoadFromFile(src); err == nil {
			t, err = b.c.AddTorrent(mi)
		}
	}
	if err != nil {
		return err
	}

	task.Extra.Store("获取元数据…")
	select {
	case <-t.GotInfo():
	case <-ctx.Done():
		return ctx.Err()
	}
	task.Name = t.Name()
	total := t.Length()
	task.SetTotal(total)
	t.DownloadAll()

	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			s := t.Stats()
			task.Extra.Store(fmt.Sprintf("peers %d/%d", s.ActivePeers, s.TotalPeers))
			cur := t.BytesCompleted()
			task.SetDone(cur)
			if cur >= total {
				ui.Success("%s", task.Name)
				return b.seed(ctx, t, task, ui)
			}
		}
	}
}

// 做种直到达到分享率
func (b *BTClient) seed(ctx context.Context, t *torrent.Torrent, task *Task, ui *UI) error {
	if b.opt.SeedRatio <= 0 {
		t.Drop()
		return nil
	}
	ui.Info("%s 做种中, 目标分享率 %.2f", task.Name, b.opt.SeedRatio)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			s := t.Stats()
			up := s.BytesWrittenData.Int64()
			ratio := float64(up) / float64(t.Length())
			task.Extra.Store(fmt.Sprintf("做种 ratio %.2f", ratio))
			if ratio >= b.opt.SeedRatio {
				t.Drop()
				return nil
			}
		}
	}
}
