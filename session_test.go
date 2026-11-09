package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGIDOf(t *testing.T) {
	g := gidOf("https://example.com/a.zip")
	if len(g) != 16 {
		t.Fatalf("GID 长度应为 16, 实际 %d", len(g))
	}
	if g != gidOf("https://example.com/a.zip") {
		t.Fatal("相同 URI 的 GID 应一致")
	}
	if g == gidOf("https://example.com/b.zip") {
		t.Fatal("不同 URI 的 GID 不应相同")
	}
}

func TestSessionRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "session.json")
	entries := []SessionEntry{
		{
			GID: gidOf("https://example.com/a"), URI: "https://example.com/a", Kind: "http", Status: "active",
			Dir: "./dl", Out: "x.zip", Checksum: "sha256=abc", Headers: []string{"Cookie: a=b"},
		},
		{GID: gidOf("magnet:?xt=urn:btih:xxx"), URI: "magnet:?xt=urn:btih:xxx", Kind: "bt", Status: "waiting"},
	}
	if err := saveSession(path, entries); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("临时文件应在 rename 后消失")
	}
	s, err := loadSession(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != sessionVersion {
		t.Fatalf("版本应为 %d, 实际 %d", sessionVersion, s.Version)
	}
	if !reflect.DeepEqual(s.Entries, entries) {
		t.Fatalf("条目不一致:\n写入 %+v\n读出 %+v", entries, s.Entries)
	}
}

func TestSaveSessionEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	if err := saveSession(path, nil); err != nil {
		t.Fatal(err)
	}
	s, err := loadSession(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Entries == nil || len(s.Entries) != 0 {
		t.Fatal("空会话应保存为 [] 而非 null")
	}
}

func TestLoadSessionCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	if err := os.WriteFile(path, []byte("{invalid"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSession(path); err == nil {
		t.Fatal("损坏的会话文件应报错")
	}
}

func TestLoadSessionMissing(t *testing.T) {
	_, err := loadSession(filepath.Join(t.TempDir(), "nope.json"))
	if !os.IsNotExist(err) {
		t.Fatalf("期望 NotExist, 实际 %v", err)
	}
}

func TestTrackerSnapshot(t *testing.T) {
	st := newSessionTracker(filepath.Join(t.TempDir(), "session.json"))
	mk := func(uri string) *Task {
		task := &Task{Name: uri, Kind: "HTTP"}
		st.add(task, entryFor(uri, false, &Options{Dir: "."}))
		return task
	}

	done := mk("https://example.com/done")
	done.SetState(StateDone)

	active := mk("https://example.com/active")
	st.markStarted(active)
	active.SetState(StateActive)

	failed := mk("https://example.com/failed")
	st.markStarted(failed)
	failed.Fail(errors.New("boom"))

	queued := mk("https://example.com/queued")
	queued.Fail(context.Canceled) // 排队中被取消, 未开始

	interrupted := mk("https://example.com/interrupted")
	st.markStarted(interrupted)
	interrupted.Fail(context.Canceled) // 下载中被用户中断

	mk("https://example.com/waiting")

	entries := st.snapshot()
	if len(entries) != 5 {
		t.Fatalf("应保存 5 个未完成任务, 实际 %d", len(entries))
	}
	status := make(map[string]SessionEntry)
	for _, e := range entries {
		status[e.URI] = e
	}
	if _, ok := status["https://example.com/done"]; ok {
		t.Fatal("已完成任务不应保存")
	}
	if e := status["https://example.com/active"]; e.Status != "active" {
		t.Fatalf("active 状态错误: %+v", e)
	}
	if e := status["https://example.com/failed"]; e.Status != "error" || e.Error != "boom" {
		t.Fatalf("失败任务应记录 error 及原因: %+v", e)
	}
	if e := status["https://example.com/queued"]; e.Status != "waiting" || e.Error != "" {
		t.Fatalf("排队中取消应记为 waiting: %+v", e)
	}
	if e := status["https://example.com/interrupted"]; e.Status != "waiting" || e.Error != "" {
		t.Fatalf("下载中中断应记为 waiting: %+v", e)
	}
	if e := status["https://example.com/waiting"]; e.Status != "waiting" {
		t.Fatalf("等待任务状态错误: %+v", e)
	}

	n, err := st.save()
	if err != nil || n != 5 {
		t.Fatalf("save 应返回 5 条, 实际 %d, err %v", n, err)
	}
	if _, err := loadSession(st.path); err != nil {
		t.Fatalf("保存的会话应可读: %v", err)
	}
}

func TestTrackerDedup(t *testing.T) {
	st := newSessionTracker(filepath.Join(t.TempDir(), "session.json"))
	uri := "https://example.com/a"
	st.add(&Task{}, entryFor(uri, false, &Options{}))
	st.add(&Task{}, entryFor(uri, false, &Options{}))
	if len(st.items) != 1 {
		t.Fatalf("相同 GID 应去重, 实际 %d 条", len(st.items))
	}
}

func TestBuildResumeJobs(t *testing.T) {
	opt := &Options{Dir: "./dl"}
	uriA := "https://example.com/a"
	uriM := "magnet:?xt=urn:btih:abc"
	s := &Session{Entries: []SessionEntry{
		{
			GID: gidOf(uriA), URI: uriA, Kind: "http", Status: "active",
			Dir: "./other", Out: "x.zip", Checksum: "md5=abc", Headers: []string{"Cookie: a=b"},
		},
		{GID: gidOf(uriA), URI: uriA, Kind: "http", Status: "waiting"}, // 重复 GID
		{GID: gidOf(uriM), URI: uriM, Kind: "bt", Status: "waiting", Dir: "./elsewhere"},
	}}
	jobs := buildResumeJobs(s, opt, []string{uriA, "https://example.com/new"})
	if len(jobs) != 3 {
		t.Fatalf("应生成 3 个任务 (去重后 2 条 + 新增 1 条), 实际 %d", len(jobs))
	}
	j0 := jobs[0]
	if j0.src != uriA || j0.opt.Dir != "./other" || j0.opt.Out != "x.zip" || j0.opt.Checksum != "md5=abc" {
		t.Fatalf("条目选项未正确应用: %+v / %+v", j0, j0.opt)
	}
	if !reflect.DeepEqual(j0.opt.Headers, []string{"Cookie: a=b"}) {
		t.Fatalf("Headers 未恢复: %+v", j0.opt.Headers)
	}
	if jobs[1].opt.Dir != "./dl" {
		t.Fatal("BT 任务应使用全局目录")
	}
	if jobs[2].src != "https://example.com/new" || jobs[2].opt != opt {
		t.Fatal("新增任务应使用全局选项")
	}
	if opt.Out != "" || opt.Checksum != "" || opt.Dir != "./dl" {
		t.Fatal("全局选项不应被条目修改")
	}
}
