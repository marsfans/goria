package main

// 会话持久化: 只记录任务列表与参数, 字节级进度仍由 .goria 控制文件负责
import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const sessionVersion = 1

type SessionEntry struct {
	GID      string   `json:"gid"`
	URI      string   `json:"uri"`
	Kind     string   `json:"kind"`   // http | bt
	Status   string   `json:"status"` // waiting | active | error
	Dir      string   `json:"dir,omitempty"`
	Out      string   `json:"out,omitempty"`
	Checksum string   `json:"checksum,omitempty"`
	Headers  []string `json:"headers,omitempty"`
	Error    string   `json:"error,omitempty"`
}

type Session struct {
	Version int            `json:"version"`
	SavedAt time.Time      `json:"saved-at"`
	Entries []SessionEntry `json:"entries"`
}

func gidOf(uri string) string {
	sum := sha1.Sum([]byte(uri))
	return hex.EncodeToString(sum[:])[:16]
}

func defaultSessionPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "goria", "session.json")
	}
	return "session.json"
}

func loadSession(path string) (*Session, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("会话文件损坏: %w", err)
	}
	return &s, nil
}

// 先写临时文件再 rename, 避免定时保存与进程退出撞上产生半截 JSON
func saveSession(path string, entries []SessionEntry) error {
	if entries == nil {
		entries = []SessionEntry{}
	}
	b, err := json.MarshalIndent(Session{Version: sessionVersion, SavedAt: time.Now(), Entries: entries}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type trackedTask struct {
	task    *Task
	entry   SessionEntry
	started bool
}

type SessionTracker struct {
	mu     sync.Mutex
	saveMu sync.Mutex
	path   string
	items  []*trackedTask
}

func newSessionTracker(path string) *SessionTracker {
	return &SessionTracker{path: path}
}

func (st *SessionTracker) add(t *Task, e SessionEntry) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, it := range st.items {
		if it.entry.GID == e.GID {
			return
		}
	}
	st.items = append(st.items, &trackedTask{task: t, entry: e})
}

func (st *SessionTracker) markStarted(t *Task) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, it := range st.items {
		if it.task == t {
			it.started = true
			return
		}
	}
}

func (st *SessionTracker) snapshot() []SessionEntry {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]SessionEntry, 0, len(st.items))
	for _, it := range st.items {
		switch TaskState(it.task.state.Load()) {
		case StateDone:
			continue
		case StateFailed:
			msg, _ := it.task.err.Load().(string)
			if !it.started || msg == context.Canceled.Error() || msg == context.DeadlineExceeded.Error() {
				// 排队中被取消或用户中断不算失败, 留给 resume 重新排队
				it.entry.Status = "waiting"
				it.entry.Error = ""
			} else {
				it.entry.Status = "error"
				it.entry.Error = msg
			}
		case StateActive:
			it.entry.Status = "active"
		default:
			it.entry.Status = "waiting"
		}
		out = append(out, it.entry)
	}
	return out
}

func (st *SessionTracker) save() (int, error) {
	st.saveMu.Lock()
	defer st.saveMu.Unlock()
	entries := st.snapshot()
	if err := saveSession(st.path, entries); err != nil {
		return 0, err
	}
	return len(entries), nil
}
