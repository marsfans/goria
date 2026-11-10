package main

// UI 单元测试: 统一计数包装、速度采样与 ETA 热身、多文件进度隔离、
// 聚合统计、百分比钳制、CJK 宽度截断、mpb 条的高度封顶溢出分配

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/mattn/go-runewidth"
	"github.com/vbauerster/mpb/v8"
)

type memWriterAt struct{ buf []byte }

func (m *memWriterAt) WriteAt(p []byte, off int64) (int, error) {
	for int64(len(m.buf)) < off+int64(len(p)) {
		m.buf = append(m.buf, 0)
	}
	copy(m.buf[off:], p)
	return len(p), nil
}

func TestCountingWriters(t *testing.T) {
	ui := NewUI(true)
	task := ui.NewTask("f", "HTTP")

	var buf bytes.Buffer
	w := task.CountingWriter(&buf)
	w.Write([]byte("12345"))
	w.Write([]byte("678"))
	if task.done.Load() != 8 || buf.Len() != 8 {
		t.Fatalf("CountingWriter 计数错误: done=%d buflen=%d", task.done.Load(), buf.Len())
	}

	mw := &memWriterAt{}
	wa := task.CountingWriterAt(mw)
	wa.WriteAt([]byte("abcd"), 0)
	wa.WriteAt([]byte("ef"), 4)
	if task.done.Load() != 14 || string(mw.buf) != "abcdef" {
		t.Fatalf("CountingWriterAt 错误: done=%d data=%q", task.done.Load(), mw.buf)
	}
}

func TestSpeedWarmupAndResetFile(t *testing.T) {
	ui := NewUI(true)
	task := ui.NewTask("big.iso", "HTTP")
	task.SetTotal(10 * 1024 * 1024)
	task.SetState(StateActive)

	task.Add(1024 * 1024)
	task.sampleSpeed(0.2)
	if got := task.etaText(); got != "--:--" {
		t.Fatalf("热身期 ETA 应为 --:--, 实际 %s", got)
	}
	for i := 0; i < 5; i++ {
		task.Add(1024 * 1024)
		task.sampleSpeed(0.2)
	}
	if got := task.etaText(); got == "--:--" {
		t.Fatal("热身后应显示 ETA")
	}
	if got := task.pctOrStateText(); got != "60.0%" {
		t.Fatalf("进度应为 60.0%%, 实际 %s", got)
	}
	if task.speedNow() <= 0 {
		t.Fatal("EWMA 速度应为正")
	}

	// 切换到新文件: 进度清零, 采样重置 (速度归零、ETA 回热身)
	task.ResetFile("next.iso")
	if task.done.Load() != 0 || task.total.Load() != 0 {
		t.Fatal("ResetFile 应清零进度")
	}
	task.sampleSpeed(0.2)
	if got := task.etaText(); got != "--:--" {
		t.Fatalf("重置后 ETA 应回到热身态, 实际 %s", got)
	}
	if got := task.pctOrStateText(); got != "--" {
		t.Fatalf("重置后总量未知应显示 --, 实际 %s", got)
	}
}

func TestAggregateStats(t *testing.T) {
	ui := NewUI(true)
	a := ui.NewTask("a", "HTTP")
	a.SetTotal(100)
	a.Add(50)
	a.SetState(StateDone)
	b := ui.NewTask("b", "HTTP")
	b.SetTotal(300)
	b.Add(150)
	b.SetState(StateActive)
	c := ui.NewTask("c", "HTTP") // 总量未知: 不计入 sumTotal
	c.SetState(StateWaiting)
	s := aggregateStats([]*Task{a, b, c})
	if s.done != 1 || s.active != 1 || s.waiting != 1 {
		t.Fatalf("状态计数错误: %+v", s)
	}
	if s.sumDone != 200 || s.sumTotal != 400 {
		t.Fatalf("总进度聚合错误: %d/%d, 期望 200/400", s.sumDone, s.sumTotal)
	}
}

func TestPctClamp(t *testing.T) {
	ui := NewUI(true)
	task := ui.NewTask("over.bin", "HTTP")
	task.SetTotal(100)
	task.Add(150) // 已下超过总量 (服务器谎报大小)
	task.SetState(StateActive)
	if got := task.pctOrStateText(); got != "100.0%" {
		t.Fatalf("百分比应钳制为 100.0%%, 实际 %s", got)
	}
}

func TestTruncDisplayWidth(t *testing.T) {
	if got := trunc("中文文件名测试长长长", 10); runewidth.StringWidth(got) > 10 {
		t.Fatalf("CJK 截断宽度超限: %q (宽 %d)", got, runewidth.StringWidth(got))
	} else if !strings.HasSuffix(got, "…") {
		t.Fatalf("截断应以 … 收尾: %q", got)
	}
	if got := trunc("short", 10); got != "short" {
		t.Fatalf("短串不应动: %q", got)
	}
	if got := trunc("abcdefghijklmnop", 8); got != "abcdefg…" {
		t.Fatalf("ASCII 截断错误: %q", got)
	}
}

func TestAttachOverflowCap(t *testing.T) {
	u := NewUI(true)
	u.height = 6 // 任务条上限 = 6-3 = 3
	u.p = mpb.New(mpb.WithOutput(io.Discard))
	u.bars = map[*Task]*mpb.Bar{}
	u.makeSumBarLocked()
	defer u.p.Shutdown()

	var tasks []*Task
	for i := 0; i < 10; i++ {
		tasks = append(tasks, u.NewTask(string(rune('a'+i))+".bin", "HTTP"))
	}
	if len(u.bars) != 3 {
		t.Fatalf("任务条应封顶为 3, 实际 %d", len(u.bars))
	}
	if len(u.overTasks) != 7 || u.overBar == nil {
		t.Fatalf("其余 7 个任务应进溢出组: over=%d overBar=%v", len(u.overTasks), u.overBar != nil)
	}
	// 收尾定格不应 panic, 且任务条进入完成态
	tasks[0].SetTotal(10)
	tasks[0].Add(10)
	tasks[0].SetState(StateDone)
	u.syncOnce(0.1, true)
	if !u.bars[tasks[0]].AbortedOrCompleted() {
		t.Fatal("定格后任务条应为完成态")
	}
}
