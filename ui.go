package main

// 终端 UI: 进度渲染交给 vbauerster/mpb — 装饰器全部定宽, 只有条在动,
// 名称/百分比/速度等文字钉在原位; 日志经容器 Write 打印到进度区上方。
// Task 仍是引擎与 UI 的唯一契约 (原子计数); 同步 goroutine 每 100ms 采样
// 速度 (实测 dt + EWMA) 并把计数推进 mpb。顶栏做成一条聚合条 (总进度),
// 任务多到超过终端高度时多余任务折叠成一条溢出聚合条。
// 非 TTY 或 quiet 时不启用 mpb: 日志直接打印, 结尾仍用 pterm 汇总表。

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mattn/go-runewidth"
	"github.com/pterm/pterm"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
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
	epoch atomic.Int64 // ResetFile 时递增, 同步侧据此重置自己的速度采样

	// 以下字段仅 UI 同步 goroutine 读写
	lastBytes int64
	speed     float64 // EWMA bytes/s
	seenEpoch int64
	barFinal  bool

	frames    atomic.Int64  // 本 epoch 内活动采样数 (ETA 热身用)
	speedView atomic.Uint64 // math.Float64bits(speed), 供 mpb 装饰器无锁读
}

func (t *Task) Add(n int64)          { t.done.Add(n) }
func (t *Task) SetDone(n int64)      { t.done.Store(n) }
func (t *Task) SetTotal(n int64)     { t.total.Store(n) }
func (t *Task) SetConns(n int64)     { t.conns.Store(n) }
func (t *Task) SetState(s TaskState) { t.state.Store(int32(s)) }
func (t *Task) Fail(err error)       { t.err.Store(err.Error()); t.SetState(StateFailed) }

// ResetFile 在同一任务内切换到下一个文件 (如 Metalink 多文件): 进度清零,
// 同步侧在下一次采样察觉 epoch 变化后重置速度采样, 不会把上个文件的字节算进来
func (t *Task) ResetFile(name string) {
	t.Name = name
	t.done.Store(0)
	t.total.Store(0)
	t.conns.Store(0)
	t.epoch.Add(1)
}

// sampleSpeed 用实测帧间隔 dt 更新 EWMA 速度 (仅 UI 同步 goroutine 调用)
func (t *Task) sampleSpeed(dt float64) {
	cur := t.done.Load()
	if ep := t.epoch.Load(); ep != t.seenEpoch {
		t.seenEpoch = ep
		t.lastBytes = cur
		t.speed = 0
		t.frames.Store(0)
	}
	inst := float64(cur-t.lastBytes) / dt
	t.lastBytes = cur
	t.speed = 0.7*t.speed + 0.3*inst
	if TaskState(t.state.Load()) == StateActive {
		t.frames.Add(1)
	}
	t.speedView.Store(math.Float64bits(t.speed))
}

func (t *Task) speedNow() float64 { return math.Float64frombits(t.speedView.Load()) }

// etaText 热身 (约 5 次采样) 后才给 ETA, 避免 EWMA 未收敛时乱跳
func (t *Task) etaText() string {
	total, cur := t.total.Load(), t.done.Load()
	sp := t.speedNow()
	if t.frames.Load() < 5 || sp <= 1 || total <= cur {
		return "--:--"
	}
	return fmtDur(time.Duration(float64(total-cur)/sp) * time.Second)
}

// pctOrStateText 条后第一列: 活动时百分比 (钳制 100), 否则终态/等待标记
func (t *Task) pctOrStateText() string {
	switch TaskState(t.state.Load()) {
	case StateDone:
		return "✔ 完成"
	case StateFailed:
		return "✘ 失败"
	case StateWaiting:
		return "等待中…"
	}
	total, cur := t.total.Load(), t.done.Load()
	if total <= 0 {
		return "--"
	}
	pct := float64(cur) / float64(total)
	if pct > 1 {
		pct = 1 // 已下超过总量 (服务器谎报大小等) 时钳制
	}
	return fmt.Sprintf("%.1f%%", pct*100)
}

func (t *Task) speedText() string {
	if TaskState(t.state.Load()) != StateActive {
		return ""
	}
	return humanBytes(t.speedNow()) + "/s"
}

// infoText 条后信息列: 已下/总量、ETA、连接数与 Extra; 终态时是大小/错误
func (t *Task) infoText() string {
	total, cur := t.total.Load(), t.done.Load()
	switch TaskState(t.state.Load()) {
	case StateDone:
		return humanBytes(float64(cur))
	case StateFailed:
		e, _ := t.err.Load().(string)
		return trunc(e, 50)
	case StateWaiting:
		return ""
	}
	size := humanBytes(float64(cur))
	if total > 0 {
		size += "/" + humanBytes(float64(total))
	}
	info := " " + size
	if c := t.conns.Load(); c > 0 {
		info += fmt.Sprintf("  连接 %d", c)
	}
	info += "  ETA " + t.etaText()
	if ex, _ := t.Extra.Load().(string); ex != "" {
		info += "  " + ex
	}
	return info
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

// uiStats 一组任务的聚合统计 (顶栏聚合条与溢出条共用)
type uiStats struct {
	active, waiting, done, failed int
	sumDone, sumTotal             int64 // 仅统计已知大小的任务
}

func aggregateStats(tasks []*Task) uiStats {
	var s uiStats
	for _, t := range tasks {
		switch TaskState(t.state.Load()) {
		case StateActive:
			s.active++
		case StateWaiting:
			s.waiting++
		case StateDone:
			s.done++
		case StateFailed:
			s.failed++
		}
		if tot := t.total.Load(); tot > 0 {
			s.sumTotal += tot
			s.sumDone += min(t.done.Load(), tot)
		}
	}
	return s
}

type statsSnap struct {
	uiStats
	speed float64 // 活动任务速度之和
	n     int     // 任务总数
}

type UI struct {
	mu        sync.Mutex // 护 tasks/bars/overTasks/p
	tasks     []*Task
	quiet     bool
	silent    bool // curl -s: 丢弃普通日志
	showError bool // curl -S: silent 时仍保留错误日志
	tty       bool
	height    int // 终端行数, 0 = 未知 (不封顶)

	logOut    io.Writer // 直打路径的日志出口, nil = os.Stdout (测试可替换捕获)
	p         *mpb.Progress
	bars      map[*Task]*mpb.Bar
	overTasks []*Task
	sumBar    *mpb.Bar
	overBar   *mpb.Bar
	sumFinal  bool
	overFinal bool
	statsSnap atomic.Value // statsSnap
	overSnap  atomic.Value // uiStats
	syncStop  chan struct{}
	syncDone  chan struct{}
}

func NewUI(quiet bool) *UI {
	if !isTTY() {
		pterm.DisableStyling()
	}
	u := &UI{quiet: quiet, tty: isTTY()}
	if u.tty {
		if _, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			u.height = h
		}
	}
	u.statsSnap.Store(statsSnap{})
	u.overSnap.Store(uiStats{})
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
	if u.p != nil {
		u.attachLocked(t)
	}
	u.mu.Unlock()
	return t
}

// 日志: mpb 启用时经容器 Write 打印到进度区上方 (下个刷新周期冲出), 否则直打
func (u *UI) log(p pterm.PrefixPrinter, format string, a ...any) {
	line := strings.TrimRight(p.Sprintf(format, a...), "\n")
	u.mu.Lock()
	prog := u.p
	u.mu.Unlock()
	if prog != nil {
		prog.Write([]byte(line + "\n"))
		return
	}
	w := u.logOut
	if w == nil {
		w = os.Stdout
	}
	fmt.Fprintln(w, line)
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
	u.mu.Lock()
	tasks := append([]*Task(nil), u.tasks...)
	u.mu.Unlock()
	data := pterm.TableData{{"类型", "名称", "大小", "状态"}}
	for _, t := range tasks {
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

// taskBarCap 任务条行数上限: 顶栏聚合条 1 行 + 溢出条预留 1 行 + 余量 1 行
func (u *UI) taskBarCap() int {
	if u.height <= 0 {
		return 1 << 30
	}
	return max(1, u.height-3)
}

func barStyle() mpb.BarStyleComposer {
	return mpb.BarStyle().Lbound("").Filler("█").Tip("█").Padding("░").Rbound("")
}

// attachLocked 给任务建条; 超过高度上限的进溢出组 (调用方持 u.mu)
func (u *UI) attachLocked(t *Task) {
	if len(u.bars) < u.taskBarCap() {
		u.bars[t] = u.makeTaskBar(t)
		return
	}
	u.overTasks = append(u.overTasks, t)
	if u.overBar == nil {
		u.overBar = u.p.New(0,
			barStyle(),
			mpb.BarWidth(24),
			mpb.PrependDecorators(decor.Any(func(decor.Statistics) string {
				s := u.overSnap.Load().(uiStats)
				n := s.active + s.waiting + s.done + s.failed
				return fmt.Sprintf("… 另有 %d 个任务 (完成 %d · 失败 %d · 等待 %d · 活动 %d)", n, s.done, s.failed, s.waiting, s.active)
			}, decor.WC{W: 46})),
		)
	}
}

func (u *UI) makeTaskBar(t *Task) *mpb.Bar {
	return u.p.New(max(t.total.Load(), 0),
		barStyle(),
		mpb.BarWidth(24),
		mpb.PrependDecorators(
			decor.Any(func(decor.Statistics) string { return t.Kind }, decor.WC{W: 4, C: decor.DSyncSpace}),
			decor.Any(func(decor.Statistics) string { return trunc(t.Name, 20) }, decor.WC{W: 20, C: decor.DSyncSpace}),
		),
		mpb.AppendDecorators(
			decor.Any(func(decor.Statistics) string { return t.pctOrStateText() }, decor.WC{W: 8, C: decor.DSyncSpaceR}),
			decor.Any(func(decor.Statistics) string { return t.speedText() }, decor.WC{W: 11, C: decor.DSyncSpaceR}),
			decor.Any(func(decor.Statistics) string { return t.infoText() }),
		),
	)
}

func (u *UI) makeSumBarLocked() {
	u.sumBar = u.p.New(0,
		barStyle(),
		mpb.BarWidth(24),
		mpb.PrependDecorators(decor.Any(func(decor.Statistics) string {
			s := u.statsSnap.Load().(statsSnap)
			return fmt.Sprintf("goria  活动 %d · 完成 %d/%d · 总速度 %s/s",
				s.active, s.done+s.failed, s.n, humanBytes(s.speed))
		}, decor.WC{W: 46})),
		mpb.AppendDecorators(decor.Any(func(decor.Statistics) string {
			s := u.statsSnap.Load().(statsSnap)
			if s.sumTotal <= 0 {
				return ""
			}
			return fmt.Sprintf("总进度 %.1f%% (%s/%s)",
				float64(s.sumDone)/float64(s.sumTotal)*100, humanBytes(float64(s.sumDone)), humanBytes(float64(s.sumTotal)))
		})),
	)
}

func (u *UI) Start() {
	if u.quiet || !u.tty {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.p != nil {
		return
	}
	u.p = mpb.New(mpb.WithOutput(os.Stdout), mpb.WithRefreshRate(120*time.Millisecond))
	u.bars = map[*Task]*mpb.Bar{}
	u.makeSumBarLocked()
	for _, t := range u.tasks {
		u.attachLocked(t)
	}
	u.syncStop = make(chan struct{})
	u.syncDone = make(chan struct{})
	go u.syncLoop()
}

func (u *UI) Stop() {
	u.mu.Lock()
	p := u.p
	u.mu.Unlock()
	if p == nil {
		return
	}
	close(u.syncStop)
	<-u.syncDone
	u.syncOnce(0.1, true)
	u.mu.Lock()
	u.p = nil
	u.mu.Unlock()
	p.Wait()
}

func (u *UI) syncLoop() {
	defer close(u.syncDone)
	tk := time.NewTicker(100 * time.Millisecond)
	defer tk.Stop()
	last := time.Now()
	for {
		select {
		case <-u.syncStop:
			return
		case now := <-tk.C:
			dt := now.Sub(last).Seconds()
			last = now
			if dt < 0.05 {
				dt = 0.05
			}
			u.syncOnce(dt, false)
		}
	}
}

// syncOnce 采样全部任务速度、刷新聚合快照, 并把计数推进 mpb; final 时定格所有条
func (u *UI) syncOnce(dt float64, final bool) {
	u.mu.Lock()
	tasks := append([]*Task(nil), u.tasks...)
	over := append([]*Task(nil), u.overTasks...)
	sumBar, overBar := u.sumBar, u.overBar
	bars := u.bars
	u.mu.Unlock()

	var speedSum float64
	for _, t := range tasks {
		t.sampleSpeed(dt)
		if TaskState(t.state.Load()) == StateActive {
			speedSum += t.speedNow()
		}
	}
	stats := aggregateStats(tasks)
	u.statsSnap.Store(statsSnap{stats, speedSum, len(tasks)})
	overStats := aggregateStats(over)
	u.overSnap.Store(overStats)

	for _, t := range tasks {
		bar := bars[t]
		if bar == nil {
			continue
		}
		st := TaskState(t.state.Load())
		if final || st == StateDone || st == StateFailed {
			finalizeTaskBar(t, bar)
		} else {
			if tot := t.total.Load(); tot > 0 {
				bar.SetTotal(tot, false)
			}
			bar.SetCurrent(t.done.Load())
		}
	}
	if sumBar != nil {
		if stats.sumTotal > 0 {
			sumBar.SetTotal(stats.sumTotal, false)
			sumBar.SetCurrent(stats.sumDone)
		} else {
			sumBar.SetTotal(int64(max(len(tasks), 1)), false)
			sumBar.SetCurrent(int64(stats.done + stats.failed))
		}
		if final && !u.sumFinal {
			u.sumFinal = true
			tot := sumBar.Current()
			if s := stats.sumTotal; s > 0 {
				tot = s
			}
			if tot <= 0 {
				tot = 1
			}
			sumBar.SetTotal(tot, true)
		}
	}
	if overBar != nil {
		overBar.SetTotal(int64(max(len(over), 1)), false)
		overBar.SetCurrent(int64(overStats.done + overStats.failed))
		if final && !u.overFinal {
			u.overFinal = true
			overBar.SetTotal(int64(max(len(over), 1)), true)
		}
	}
}

// finalizeTaskBar 把任务条定格为终态行 (完成显示满条, 失败保留已下部分)
func finalizeTaskBar(t *Task, bar *mpb.Bar) {
	if t.barFinal {
		return
	}
	t.barFinal = true
	bar.SetCurrent(t.done.Load())
	total := max(t.total.Load(), t.done.Load())
	if total <= 0 {
		total = 1
	}
	bar.SetTotal(total, true)
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

// trunc 按显示宽度截断 (CJK 字符占 2 格), 超出时以 … 收尾且总宽不超过 n,
// 与 mpb 装饰器的列宽口径一致, 中文文件名不会把进度行顶歪
func trunc(s string, n int) string {
	if runewidth.StringWidth(s) <= n {
		return s
	}
	var b strings.Builder
	w := 0
	for _, r := range s {
		rw := runewidth.RuneWidth(r)
		if w+rw > n-1 {
			break
		}
		b.WriteRune(r)
		w += rw
	}
	return b.String() + "…"
}
