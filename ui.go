package main

// 终端 UI: 用 lipgloss 渲染多任务进度, termenv 负责颜色探测与光标控制
import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/pterm/pterm"
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

	lastBytes int64
	speed     float64 // EWMA bytes/s
}

func (t *Task) Add(n int64)          { t.done.Add(n) }
func (t *Task) SetDone(n int64)      { t.done.Store(n) }
func (t *Task) SetTotal(n int64)     { t.total.Store(n) }
func (t *Task) SetConns(n int64)     { t.conns.Store(n) }
func (t *Task) SetState(s TaskState) { t.state.Store(int32(s)) }
func (t *Task) Fail(err error)       { t.err.Store(err.Error()); t.SetState(StateFailed) }

type UI struct {
	mu      sync.Mutex
	tasks   []*Task
	out     *termenv.Output
	lines   int
	stop    chan struct{}
	stopped chan struct{}
	logs    []string
	quiet   bool
	tty     bool

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
func (u *UI) Info(f string, a ...any)    { u.log(pterm.Info, f, a...) }
func (u *UI) Success(f string, a ...any) { u.log(pterm.Success, f, a...) }
func (u *UI) Warn(f string, a ...any)    { u.log(pterm.Warning, f, a...) }
func (u *UI) Error(f string, a ...any)   { u.log(pterm.Error, f, a...) }

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
				u.render(0.2)
			case <-u.stop:
				u.render(0.2)
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

func (u *UI) render(dt float64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.quiet || !u.tty {
		for _, l := range u.logs {
			fmt.Fprintln(u.out, l)
		}
		u.logs = nil
		return
	}
	// 回到进度区起点并清除
	if u.lines > 0 {
		u.out.ClearLines(u.lines)
		fmt.Fprint(u.out, "\r")
	}
	for _, l := range u.logs {
		fmt.Fprintln(u.out, l)
	}
	u.logs = nil

	var b strings.Builder
	var totalSpeed float64
	active, finished := 0, 0
	for _, t := range u.tasks {
		cur := t.done.Load()
		inst := float64(cur-t.lastBytes) / dt
		t.lastBytes = cur
		t.speed = 0.7*t.speed + 0.3*inst
		st := TaskState(t.state.Load())
		switch st {
		case StateActive:
			active++
			totalSpeed += t.speed
		case StateDone, StateFailed:
			finished++
		}
		b.WriteString(u.line(t, st))
		b.WriteByte('\n')
	}
	head := u.sHead.Render("goria") + u.sDim.Render(fmt.Sprintf("  活动 %d · 完成 %d/%d · 总速度 ", active, finished, len(u.tasks))) +
		u.sSpeed.UnsetWidth().Render(humanBytes(totalSpeed)+"/s")
	out := head + "\n" + b.String()
	fmt.Fprint(u.out, out)
	u.lines = strings.Count(out, "\n")
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
	if t.speed > 1 && total > 0 {
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
