package main

// 终端 UI: 用 lipgloss 渲染多任务进度, termenv 负责颜色探测与光标控制
import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/pterm/pterm"
	"golang.org/x/term"
)

type TaskState int

const (
	StateWaiting TaskState = iota
	StateActive
	StateDone
	StateFailed
)

type Task struct {
	Name  string
	Kind  string // HTTP / BT
	total atomic.Int64
	done  atomic.Int64
	conns atomic.Int64
	Extra atomic.Value // string, 额外信息 (如 BT peers)
	state atomic.Int32
	err   atomic.Value
	epoch atomic.Int64 // ResetFile 时递增, 渲染侧据此重置自己的速度采样

	// 以下字段仅渲染 goroutine 读写
	lastBytes int64
	speed     float64 // EWMA bytes/s
	seenEpoch int64
	frames    int // 本 epoch 内活动帧数 (ETA 热身用)
}

func (t *Task) Add(n int64)          { t.done.Add(n) }
func (t *Task) SetDone(n int64)      { t.done.Store(n) }
func (t *Task) SetTotal(n int64)     { t.total.Store(n) }
func (t *Task) SetConns(n int64)     { t.conns.Store(n) }
func (t *Task) SetState(s TaskState) { t.state.Store(int32(s)) }
func (t *Task) Fail(err error)       { t.err.Store(err.Error()); t.SetState(StateFailed) }

// ResetFile 在同一任务内切换到下一个文件 (如 Metalink 多文件): 进度清零,
// 渲染侧在下一帧察觉 epoch 变化后重置速度采样, 不会把上个文件的字节算进来
func (t *Task) ResetFile(name string) {
	t.Name = name
	t.done.Store(0)
	t.total.Store(0)
	t.conns.Store(0)
	t.epoch.Add(1)
}

// 统一计数入口: 引擎把字节流过包装器即自动计入进度, 不再各自手调 Add,
// 避免漏调与口径不一致 (回滚修正如 --range 不支持时的 Add(-Done) 仍可手动)
type taskWriter struct {
	w io.Writer
	t *Task
}

func (t *Task) CountingWriter(w io.Writer) io.Writer { return taskWriter{w, t} }

func (tw taskWriter) Write(p []byte) (int, error) {
	n, err := tw.w.Write(p)
	if n > 0 {
		tw.t.Add(int64(n))
	}
	return n, err
}

type taskWriterAt struct {
	w io.WriterAt
	t *Task
}

func (t *Task) CountingWriterAt(w io.WriterAt) io.WriterAt { return taskWriterAt{w, t} }

func (tw taskWriterAt) WriteAt(p []byte, off int64) (int, error) {
	n, err := tw.w.WriteAt(p, off)
	if n > 0 {
		tw.t.Add(int64(n))
	}
	return n, err
}

type UI struct {
	mu        sync.Mutex // 只护 tasks 与 logs 两个切片
	tasks     []*Task
	out       *termenv.Output
	lines     int
	stop      chan struct{}
	stopped   chan struct{}
	logs      []string
	quiet     bool
	silent    bool // curl -s: 丢弃普通日志
	showError bool // curl -S: silent 时仍保留错误日志
	tty       bool
	height    int // 终端行数, 0 = 未知 (不封顶)

	// 以下字段仅渲染 goroutine 读写
	lastFrame string
	lastAt    time.Time

	sName, sBarOn, sBarOff, sPct, sSpeed, sDim, sOK, sErr, sKind, sHead lipgloss.Style
}

func NewUI(quiet bool) *UI {
	out := termenv.NewOutput(os.Stdout)
	lipgloss.SetColorProfile(out.Profile)
	if !isTTY() {
		pterm.DisableStyling()
	}
	u := &UI{
		out: out, quiet: quiet,
		tty:     isTTY(),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
		sName:   lipgloss.NewStyle().Width(26).Foreground(lipgloss.Color("252")),
		sBarOn:  lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4")),
		sBarOff: lipgloss.NewStyle().Foreground(lipgloss.Color("238")),
		sPct:    lipgloss.NewStyle().Width(7).Align(lipgloss.Right).Bold(true),
		sSpeed:  lipgloss.NewStyle().Width(11).Align(lipgloss.Right).Foreground(lipgloss.Color("#04B575")),
		sDim:    lipgloss.NewStyle().Foreground(lipgloss.Color("244")),
		sOK:     lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Bold(true),
		sErr:    lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F87")).Bold(true),
		sKind:   lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("#7D56F4")).Padding(0, 1),
		sHead:   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4")),
	}
	if u.tty {
		if _, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			u.height = h
		}
	}
	return u
}

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func (u *UI) NewTask(name, kind string) *Task {
	t := &Task{Name: name, Kind: kind}
	t.Extra.Store("")
	u.mu.Lock()
	u.tasks = append(u.tasks, t)
	u.mu.Unlock()
	return t
}

// 日志: 用 pterm 的前缀打印器渲染, 显示在进度区上方
func (u *UI) log(p pterm.PrefixPrinter, format string, a ...any) {
	line := strings.TrimRight(p.Sprintf(format, a...), "\n")
	u.mu.Lock()
	u.logs = append(u.logs, line)
	u.mu.Unlock()
}
func (u *UI) Info(f string, a ...any) {
	if !u.silent {
		u.log(pterm.Info, f, a...)
	}
}
func (u *UI) Success(f string, a ...any) {
	if !u.silent {
		u.log(pterm.Success, f, a...)
	}
}
func (u *UI) Warn(f string, a ...any) {
	if !u.silent {
		u.log(pterm.Warning, f, a...)
	}
}
func (u *UI) Error(f string, a ...any) {
	if !u.silent || u.showError {
		u.log(pterm.Error, f, a...)
	}
}

// Summary 用 pterm 表格输出所有任务的最终结果
func (u *UI) Summary() {
	data := pterm.TableData{{"类型", "名称", "大小", "状态"}}
	for _, t := range u.tasks {
		status := pterm.Green("✔ 完成")
		switch TaskState(t.state.Load()) {
		case StateFailed:
			e, _ := t.err.Load().(string)
			status = pterm.Red("✘ " + trunc(e, 40))
		case StateActive, StateWaiting:
			status = pterm.Yellow("■ 未完成")
		}
		data = append(data, []string{strings.TrimSpace(t.Kind), trunc(t.Name, 36), humanBytes(float64(t.done.Load())), status})
	}
	pterm.Println()
	pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(data).Render()
}

func (u *UI) Start() {
	if u.tty {
		u.out.HideCursor()
	}
	go func() {
		defer close(u.stopped)
		tk := time.NewTicker(200 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				u.render()
			case <-u.stop:
				u.render()
				return
			}
		}
	}()
}

func (u *UI) Stop() {
	close(u.stop)
	<-u.stopped
	if u.tty {
		u.out.ShowCursor()
	}
}

// render 渲染一帧: 锁内只摘走日志与任务快照, 拼装与终端写入都在锁外,
// 慢终端不会反过来堵住引擎打日志; 帧内容与上一帧相同且无新日志时整帧跳过
func (u *UI) render() {
	u.mu.Lock()
	logs := u.logs
	u.logs = nil
	tasks := append([]*Task(nil), u.tasks...)
	u.mu.Unlock()

	if u.quiet || !u.tty {
		for _, l := range logs {
			fmt.Fprintln(u.out, l)
		}
		return
	}
	now := time.Now()
	dt := 0.2
	if !u.lastAt.IsZero() {
		dt = now.Sub(u.lastAt).Seconds()
	}
	u.lastAt = now
	if dt < 0.05 {
		dt = 0.05 // 两帧紧挨 (如 Stop 的收尾帧) 时防速度尖峰
	}
	frame := u.buildFrame(tasks, dt)
	if len(logs) == 0 && frame == u.lastFrame {
		return
	}
	if u.lines > 0 {
		u.out.ClearLines(u.lines)
		fmt.Fprint(u.out, "\r")
	}
	for _, l := range logs {
		fmt.Fprintln(u.out, l)
	}
	fmt.Fprint(u.out, frame)
	u.lastFrame = frame
	u.lines = strings.Count(frame, "\n")
}

// buildFrame 用实测帧间隔 dt 更新各任务速度采样并拼出整帧文本 (仅渲染 goroutine 调用)
func (u *UI) buildFrame(tasks []*Task, dt float64) string {
	type row struct {
		text string
		st   TaskState
	}
	rows := make([]row, 0, len(tasks))
	var totalSpeed float64
	active, finished := 0, 0
	for _, t := range tasks {
		cur := t.done.Load()
		if ep := t.epoch.Load(); ep != t.seenEpoch {
			t.seenEpoch = ep
			t.lastBytes = cur
			t.speed = 0
			t.frames = 0
		}
		inst := float64(cur-t.lastBytes) / dt
		t.lastBytes = cur
		t.speed = 0.7*t.speed + 0.3*inst
		st := TaskState(t.state.Load())
		switch st {
		case StateActive:
			active++
			t.frames++
			totalSpeed += t.speed
		case StateDone, StateFailed:
			finished++
		}
		rows = append(rows, row{u.line(t, st), st})
	}
	// 展示顺序: 活动 → 等待 → 完成/失败 (组内保持原序), 封顶时先折叠终态任务
	ordered := make([]row, 0, len(rows))
	for _, want := range []TaskState{StateActive, StateWaiting, StateDone, StateFailed} {
		for _, r := range rows {
			if r.st == want {
				ordered = append(ordered, r)
			}
		}
	}
	maxRows := len(ordered)
	if u.height > 2 {
		maxRows = min(maxRows, u.height-2) // 顶栏 1 行 + 至少留 1 行余量
	}
	var b strings.Builder
	shown := ordered
	var overflow string
	if len(ordered) > maxRows {
		shown = ordered[:max(maxRows-1, 0)]
		hidden := ordered[len(shown):]
		var hd, hf, hw int
		for _, r := range hidden {
			switch r.st {
			case StateDone:
				hd++
			case StateFailed:
				hf++
			case StateWaiting:
				hw++
			}
		}
		overflow = u.sDim.Render(fmt.Sprintf("… 另有 %d 个任务 (完成 %d · 失败 %d · 等待 %d)", len(hidden), hd, hf, hw))
	}
	for _, r := range shown {
		b.WriteString(r.text)
		b.WriteByte('\n')
	}
	if overflow != "" {
		b.WriteString(overflow)
		b.WriteByte('\n')
	}
	head := u.sHead.Render("goria") + u.sDim.Render(fmt.Sprintf("  活动 %d · 完成 %d/%d · 总速度 ", active, finished, len(tasks))) +
		u.sSpeed.UnsetWidth().Render(humanBytes(totalSpeed)+"/s")
	return head + "\n" + b.String()
}

func (u *UI) line(t *Task, st TaskState) string {
	total, cur := t.total.Load(), t.done.Load()
	kind := u.sKind.Render(t.Kind)
	name := u.sName.Render(" " + trunc(t.Name, 24))
	switch st {
	case StateDone:
		return kind + name + u.sOK.Render("✔ 完成 ") + u.sDim.Render(humanBytes(float64(cur)))
	case StateFailed:
		e, _ := t.err.Load().(string)
		return kind + name + u.sErr.Render("✘ 失败 ") + u.sDim.Render(trunc(e, 50))
	case StateWaiting:
		return kind + name + u.sDim.Render("等待中…")
	}
	const w = 30
	pct := 0.0
	if total > 0 {
		pct = float64(cur) / float64(total)
	}
	fill := int(pct * w)
	bar := u.sBarOn.Render(strings.Repeat("█", fill)) + u.sBarOff.Render(strings.Repeat("░", w-fill))
	eta := "--:--"
	if t.frames >= 5 && t.speed > 1 && total > 0 { // 热身约 1s 后才显示 ETA, 避免开局乱跳
		eta = fmtDur(time.Duration(float64(total-cur)/t.speed) * time.Second)
	}
	size := humanBytes(float64(cur))
	if total > 0 {
		size += "/" + humanBytes(float64(total))
	}
	info := fmt.Sprintf(" %s  ETA %s", size, eta)
	if c := t.conns.Load(); c > 0 {
		info += fmt.Sprintf("  连接 %d", c)
	}
	if ex, _ := t.Extra.Load().(string); ex != "" {
		info += "  " + ex
	}
	return kind + name + bar + u.sPct.Render(fmt.Sprintf("%.1f%%", pct*100)) +
		u.sSpeed.Render(humanBytes(t.speed)+"/s") + u.sDim.Render(info)
}

func humanBytes(b float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	return fmt.Sprintf("%.1f%s", b, units[i])
}

func fmtDur(d time.Duration) string {
	d = d.Round(time.Second)
	h, m, s := int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
