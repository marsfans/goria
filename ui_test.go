package main

// UI 单元测试: 统一计数包装、实测 dt 下的速度/ETA 热身、多文件进度隔离、
// 高度封顶与溢出行、终态帧稳定性

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/mattn/go-runewidth"
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

	// 第 1 帧有进度但 ETA 还在热身期
	task.Add(1024 * 1024)
	f1 := ui.buildFrame([]*Task{task}, 0.2)
	if !strings.Contains(f1, "ETA --:--") {
		t.Fatalf("热身期 ETA 应为 --:--, 帧: %q", f1)
	}
	// 累计 6 帧后 ETA 出现, 百分比推进
	for i := 0; i < 5; i++ {
		task.Add(1024 * 1024)
		f1 = ui.buildFrame([]*Task{task}, 0.2)
	}
	if strings.Contains(f1, "ETA --:--") {
		t.Fatalf("热身后应显示 ETA, 帧: %q", f1)
	}
	if !strings.Contains(f1, "60.0%") {
		t.Fatalf("进度应为 60%%, 帧: %q", f1)
	}

	// 切换到新文件: 进度清零, 速度采样重置 (下一帧速度归零、ETA 回热身)
	task.ResetFile("next.iso")
	if task.done.Load() != 0 || task.total.Load() != 0 {
		t.Fatal("ResetFile 应清零进度")
	}
	f2 := ui.buildFrame([]*Task{task}, 0.2)
	if !strings.Contains(f2, "next.iso") || !strings.Contains(f2, "0.0%") {
		t.Fatalf("重置后帧错误: %q", f2)
	}
	if !strings.Contains(f2, "ETA --:--") {
		t.Fatalf("重置后 ETA 应回到热身态, 帧: %q", f2)
	}
}

func TestBuildFrameHeightCap(t *testing.T) {
	ui := NewUI(true)
	ui.height = 6 // 顶栏 1 + 任务区最多 4 行 (含溢出行)
	var tasks []*Task
	for i := 0; i < 10; i++ {
		tk := ui.NewTask(string(rune('a'+i))+".bin", "HTTP")
		tk.SetTotal(100)
		switch {
		case i < 2:
			tk.SetState(StateActive)
		case i < 5:
			tk.SetState(StateWaiting)
		default:
			tk.SetState(StateDone)
		}
		tasks = append(tasks, tk)
	}
	frame := ui.buildFrame(tasks, 0.2)
	lines := strings.Count(strings.TrimRight(frame, "\n"), "\n") + 1
	if lines > ui.height-1 {
		t.Fatalf("帧行数 %d 超过封顶 %d", lines, ui.height-1)
	}
	if !strings.Contains(frame, "另有") {
		t.Fatalf("应有溢出行, 帧: %q", frame)
	}
	if !strings.Contains(frame, "a.bin") {
		t.Fatalf("活动任务应优先显示, 帧: %q", frame)
	}
}

func TestGlobalProgressHeader(t *testing.T) {
	ui := NewUI(true)
	a := ui.NewTask("a", "HTTP")
	a.SetTotal(100)
	a.Add(50)
	a.SetState(StateDone)
	b := ui.NewTask("b", "HTTP")
	b.SetTotal(300)
	b.Add(150)
	b.SetState(StateActive)
	unknown := ui.NewTask("c", "HTTP") // total 未知不计入总进度
	unknown.SetState(StateActive)
	frame := ui.buildFrame([]*Task{a, b, unknown}, 0.2)
	if !strings.Contains(frame, "总进度 50.0%") {
		t.Fatalf("顶栏应有总进度 50.0%% (200/400), 帧: %q", frame)
	}
}

func TestRenderIntervalAdaptive(t *testing.T) {
	ui := NewUI(true)
	tk := ui.NewTask("x", "HTTP")
	tk.SetState(StateDone)
	if got := ui.renderInterval(); got != 500*time.Millisecond {
		t.Fatalf("无活动任务应 500ms, 实际 %v", got)
	}
	tk.SetState(StateActive)
	if got := ui.renderInterval(); got != 100*time.Millisecond {
		t.Fatalf("有活动任务应 100ms, 实际 %v", got)
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

func TestLinePctClamp(t *testing.T) {
	ui := NewUI(true)
	task := ui.NewTask("over.bin", "HTTP")
	task.SetTotal(100)
	task.Add(150) // 已下超过总量 (服务器谎报大小)
	task.SetState(StateActive)
	for i := 0; i < 6; i++ { // 过热身期
		ui.buildFrame([]*Task{task}, 0.2)
	}
	frame := ui.buildFrame([]*Task{task}, 0.2) // 不应 panic 且钳制在 100%
	if !strings.Contains(frame, "100.0%") {
		t.Fatalf("百分比应钳制为 100.0%%, 帧: %q", frame)
	}
}

func TestDoneFrameStable(t *testing.T) {
	ui := NewUI(true)
	task := ui.NewTask("done.bin", "HTTP")
	task.SetTotal(100)
	task.Add(100)
	task.SetState(StateDone)
	f1 := ui.buildFrame([]*Task{task}, 0.2)
	f2 := ui.buildFrame([]*Task{task}, 0.2)
	if f1 != f2 {
		t.Fatalf("终态帧应逐字稳定 (静止不重绘的前提):\n%q\n%q", f1, f2)
	}
}
