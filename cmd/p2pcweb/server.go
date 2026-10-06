package main

// 本地服务：回环 HTTP + 内嵌网页 UI + SSE 日志流 + 传输编排 API。
// 安全面：默认仅绑 127.0.0.1；全路由要求启动时生成的随机令牌（恒时比较），
// 回环部署下校验 Host 头防 DNS rebinding；无 CORS 头（同源才可读）。

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/filescodebox/kit/version"
	"github.com/filescodebox/p2p/internal/client"
)

//go:embed web/index.html
var webFS embed.FS

// Server 网页模式服务。
type Server struct {
	token     string
	loopback  bool
	port      string
	maxUpload int64
	outDir    string
	relay     string // 透传子模式的中继地址（空=按注册中心 host 推导；测试注入用）
	noPunch   bool   // 透传子模式禁用打洞（默认 false；测试确定性用）
	cfg       *cfgStore
	mgr       *Manager
}

func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// guard 令牌 + Host 校验。
func (s *Server) guard(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Query().Get("t")
		if tok == "" {
			tok = r.Header.Get("X-P2PCWEB")
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
			http.Error(w, "403：令牌无效，请从启动时打印的完整地址进入", http.StatusForbidden)
			return
		}
		if s.loopback && !s.sameLoopbackHost(r.Host) {
			// 防 DNS rebinding：回环部署下 Host 必须是本机回环名 + 本服务端口
			http.Error(w, "403：Host 校验失败", http.StatusForbidden)
			return
		}
		fn(w, r)
	}
}

// sameLoopbackHost Host 头须为回环主机名 + 本服务端口。
func (s *Server) sameLoopbackHost(hostPort string) bool {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return false
	}
	if port != s.port {
		return false
	}
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.guard(s.handleIndex))
	mux.HandleFunc("/api/state", s.guard(s.handleState))
	mux.HandleFunc("/api/config", s.guard(s.handleConfig))
	mux.HandleFunc("/api/send", s.guard(s.handleSend))
	mux.HandleFunc("/api/recv", s.guard(s.handleRecv))
	mux.HandleFunc("/api/cancel", s.guard(s.handleCancel))
	mux.HandleFunc("/api/events", s.guard(s.handleEvents))
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "内置页面缺失", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

func (s *Server) handleState(w http.ResponseWriter, _ *http.Request) {
	cfg := s.cfg.get()
	writeJSON(w, http.StatusOK, map[string]any{
		"busy":       s.mgr.Busy(),
		"role":       s.mgr.Role(),
		"code":       s.mgr.Code(),
		"server_url": cfg.ServerURL,
		"registry":   cfg.Registry,
		"out_dir":    s.outDir,
		"version":    version.Version,
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	var in struct{ ServerURL, Registry string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体非法")
		return
	}
	cfg := s.cfg.get()
	if in.ServerURL != "" {
		cfg.ServerURL = normalizeBaseURL(in.ServerURL)
	}
	if in.Registry != "" {
		cfg.Registry = normalizeBaseURL(in.Registry)
	}
	if err := s.cfg.set(cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

// normalizeBaseURL 宽容归一：补 http://、去尾斜杠（与桌面端设置页一致）。
func normalizeBaseURL(raw string) string {
	t := strings.TrimSpace(raw)
	t = strings.Trim(t, `"'`)
	t = strings.TrimRight(t, "/")
	if t == "" {
		return ""
	}
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		return t
	}
	return "http://" + t
}

// handleSend 流式收上传 → 临时目录（保留原始文件名）→ 拉起发送。
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	registry := normalizeBaseURL(r.URL.Query().Get("registry"))
	if registry == "" {
		writeErr(w, http.StatusBadRequest, "请填写直传注册中心地址")
		return
	}
	if s.mgr.Busy() {
		writeErr(w, http.StatusConflict, ErrBusy.Error())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.maxUpload+(1<<20))
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "需要 multipart 文件表单")
		return
	}
	var part *multipart.Part
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, "表单解析失败")
			return
		}
		if p.FormName() == "file" {
			part = p
			break
		}
		_ = p.Close()
	}
	if part == nil {
		writeErr(w, http.StatusBadRequest, "缺少 file 字段")
		return
	}

	tmpDir, err := os.MkdirTemp("", "p2pcweb-upload-")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "临时目录创建失败: "+err.Error())
		return
	}
	dest := filepath.Join(tmpDir, sanitizeName(part.FileName()))
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		writeErr(w, http.StatusInternalServerError, "临时文件创建失败: "+err.Error())
		return
	}
	n, err := io.Copy(f, part)
	closeErr := f.Close()
	_ = part.Close()
	if err != nil || closeErr != nil {
		_ = os.RemoveAll(tmpDir)
		writeErr(w, http.StatusBadRequest, "上传读取失败")
		return
	}
	if n > s.maxUpload {
		_ = os.RemoveAll(tmpDir)
		writeErr(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("文件超过上限 %d 字节（--max-upload 可调）", s.maxUpload))
		return
	}
	if n == 0 {
		_ = os.RemoveAll(tmpDir)
		writeErr(w, http.StatusBadRequest, "空文件")
		return
	}

	code, err := client.GenerateCode()
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		writeErr(w, http.StatusInternalServerError, "口令生成失败: "+err.Error())
		return
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }
	if err := s.mgr.Start("send", registry, code, dest, "", s.relay, s.noPunch, cleanup); err != nil {
		cleanup()
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"code": code})
}

// multipartPart 已移除（直接用 *multipart.Part）。

func (s *Server) handleRecv(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code, Registry string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体非法")
		return
	}
	code := strings.ToUpper(strings.TrimSpace(in.Code))
	registry := normalizeBaseURL(in.Registry)
	if code == "" {
		writeErr(w, http.StatusBadRequest, "请输入口令")
		return
	}
	if registry == "" {
		writeErr(w, http.StatusBadRequest, "请填写直传注册中心地址")
		return
	}
	_ = s.cfg.set(Config{ServerURL: s.cfg.get().ServerURL, Registry: registry})
	if err := s.mgr.Start("recv", registry, code, "", s.outDir, s.relay, s.noPunch, nil); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"ok": "1"})
}

func (s *Server) handleCancel(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"cancelled": s.mgr.Cancel()})
}

// handleEvents SSE：日志/口令/退出事件实时推送，15s 心跳保活。
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "不支持流式响应", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.mgr.Subscribe()
	defer s.mgr.Unsubscribe(ch)
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()

	// 快照：订阅后若传输已结束不再有事件，补一条状态让页面收敛
	writeSSE(w, fl, Event{Type: "state", Code: s.mgr.Code(), Busy: s.mgr.Busy(), Role: s.mgr.Role()})
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			writeSSE(w, fl, ev)
		case <-tick.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func writeSSE(w http.ResponseWriter, fl http.Flusher, ev Event) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
		return
	}
	fl.Flush()
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return ""
}
