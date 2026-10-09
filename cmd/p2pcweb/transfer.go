package main

// 传输编排：父进程把阻塞式 internal/client 跑在 re-exec 的隐藏子模式里
//（--transfer-child），kill 子进程即取消——与桌面端 p2pc sidecar 语义一致，
// 客户端核心（Send/Receive 无 ctx 取消）零改动。同一时刻至多一个传输。

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/pigeonbox/p2p/internal/client"
)

// ErrBusy 已有传输进行中。
var ErrBusy = errors.New("已有直传任务进行中，请等待完成或先取消")

// 子进程结果标记行（父进程按行扫描）。
const (
	doneMarker  = "P2PCWEB-DONE"  // 后可跟接收落盘路径
	errorMarker = "P2PCWEB-ERROR" // 后为错误信息
)

// Event SSE 推送事件。
type Event struct {
	Type string `json:"type"`           // state | code | log | exit
	Line string `json:"line,omitempty"` // log：日志行
	Code string `json:"code,omitempty"` // code/state：直传口令
	Busy bool   `json:"busy,omitempty"` // state：是否有传输进行中
	Role string `json:"role,omitempty"` // state：send | recv
	Exit int    `json:"exit,omitempty"` // exit：子进程退出码（0 成功）
	Path string `json:"path,omitempty"` // exit：接收落盘路径
	Err  string `json:"err,omitempty"`  // exit：失败原因
}

// Manager 单会话传输管理器。
type Manager struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	running  bool
	role     string // send | recv
	code     string
	donePath string
	cleanup  func()

	subMu sync.Mutex
	subs  map[chan Event]struct{}
}

func NewManager() *Manager { return &Manager{subs: make(map[chan Event]struct{})} }

func (m *Manager) Busy() bool   { m.mu.Lock(); defer m.mu.Unlock(); return m.running }
func (m *Manager) Role() string { m.mu.Lock(); defer m.mu.Unlock(); return m.role }
func (m *Manager) Code() string { m.mu.Lock(); defer m.mu.Unlock(); return m.code }

// Subscribe 订阅事件流。通道缓冲 64，慢消费者丢行不阻塞传输。
func (m *Manager) Subscribe() chan Event {
	ch := make(chan Event, 64)
	m.subMu.Lock()
	m.subs[ch] = struct{}{}
	m.subMu.Unlock()
	return ch
}

func (m *Manager) Unsubscribe(ch chan Event) {
	m.subMu.Lock()
	delete(m.subs, ch)
	m.subMu.Unlock()
}

func (m *Manager) broadcast(ev Event) {
	m.subMu.Lock()
	defer m.subMu.Unlock()
	for ch := range m.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Start 拉起传输子进程。kind=send|recv；cleanup 在进程退出后执行（临时文件清理）。
// relay 非空/禁打洞透传子模式（服务端默认推导中继；测试注入 fixture 中继保确定性）。
func (m *Manager) Start(kind, registry, code, path, outDir, relay string, noPunch bool, cleanup func()) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return ErrBusy
	}
	self, err := os.Executable()
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("定位自身可执行文件: %w", err)
	}
	// 统一 --k=v 形式：便于 go test 二进制以 TestMain 分发子模式（见 e2e_test.go）
	args := []string{"--transfer-child=" + kind, "--registry=" + registry, "--code=" + code}
	if kind == "send" {
		args = append(args, "--path="+path)
	} else {
		args = append(args, "--out="+outDir)
	}
	if relay != "" {
		args = append(args, "--relay="+relay)
	}
	if noPunch {
		args = append(args, "--no-punch")
	}
	cmd := exec.Command(self, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if err := cmd.Start(); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("启动传输: %w", err)
	}
	m.cmd, m.running, m.role, m.code, m.donePath, m.cleanup = cmd, true, kind, code, "", cleanup
	m.mu.Unlock()

	m.broadcast(Event{Type: "code", Code: code})
	go m.pipe(stdout)
	go m.pipe(stderr)
	go m.wait()
	return nil
}

// Cancel 终止当前传输。返回是否确有进程被终止。
func (m *Manager) Cancel() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running || m.cmd == nil || m.cmd.Process == nil {
		return false
	}
	_ = m.cmd.Process.Kill()
	return true
}

// pipe 子进程输出 → 日志事件；DONE 标记行单独记录（携带接收落盘路径）。
func (m *Manager) pipe(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, doneMarker) {
			m.mu.Lock()
			m.donePath = strings.TrimSpace(strings.TrimPrefix(line, doneMarker))
			m.mu.Unlock()
			continue
		}
		m.broadcast(Event{Type: "log", Line: line})
	}
}

func (m *Manager) wait() {
	err := m.cmd.Wait()
	m.mu.Lock()
	cleanup := m.cleanup
	path := m.donePath
	m.running, m.role, m.code, m.donePath, m.cleanup = false, "", "", "", nil
	m.mu.Unlock()

	exitCode := 0
	msg := ""
	if err != nil {
		exitCode = 1
		msg = err.Error()
		// 非 kill 的失败（对端未接入/网络等）补一行可读原因；kill=用户取消，
		// 界面按取消态处理，不再刷 "signal: killed" 噪音
		if !strings.Contains(msg, "kill") {
			m.broadcast(Event{Type: "log", Line: "✗ " + msg})
		}
	}
	if cleanup != nil {
		cleanup()
	}
	m.broadcast(Event{Type: "exit", Exit: exitCode, Path: path, Err: msg})
}

// runTransferChild 隐藏子模式：跑阻塞式 client，日志（slog）走 stdout 供父进程
// 捕获，结尾输出 DONE/ERROR 标记行。返回进程退出码。
func runTransferChild(o *options) int {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout,
		&slog.HandlerOptions{Level: slog.LevelInfo})))
	c, err := client.New(client.Options{Registry: o.registry, RelayAddr: o.relay, DisablePunch: o.noPunch})
	if err != nil {
		return childFail(err)
	}
	switch o.child {
	case "send":
		if _, err := c.Send([]string{o.path}, strings.ToUpper(o.code)); err != nil {
			return childFail(err)
		}
		fmt.Println(doneMarker)
	case "recv":
		files, err := c.Receive(strings.ToUpper(strings.TrimSpace(o.code)), o.outDir)
		if err != nil {
			return childFail(err)
		}
		if len(files) == 0 {
			return childFail(fmt.Errorf("未收到文件"))
		}
		fmt.Println(doneMarker + " " + files[0])
	default:
		return childFail(fmt.Errorf("未知传输子模式 %q", o.child))
	}
	return 0
}

func childFail(err error) int {
	fmt.Printf("%s %v\n", errorMarker, err)
	return 1
}
