// Package server 装配 p2pd 的 HTTP 面:路由、中间件、限流、指标。
// 响应约定:成功 200 + JSON;失败为对应 HTTP 状态码 + {"error": "消息"}。
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/filescodebox/kit/ratelimit"
	"github.com/filescodebox/p2p/internal/config"
	"github.com/filescodebox/p2p/internal/registry"
	"github.com/filescodebox/p2p/internal/signaling"
	"golang.org/x/time/rate"
)

const maxBodyBytes = 64 << 10 // 64KB,所有请求体上限

// limiterIdleTTL 按键限流条目的空闲回收阈值(闲置超此值的 key 被清理)。
const limiterIdleTTL = 30 * time.Minute

// newKeyedLimiter 构造按键令牌桶(kit/ratelimit,空闲键自动回收)。
// 生命周期跟随 ctx:ctx 结束时停掉清理协程——与信令/清扫协程同寿命。
func newKeyedLimiter(ctx context.Context, r rate.Limit, burst int) *ratelimit.KeyedLimiter {
	kl := ratelimit.NewKeyedLimiter(func() ratelimit.Limiter {
		return ratelimit.NewTokenBucket(r, burst)
	}, limiterIdleTTL)
	go func() {
		<-ctx.Done()
		kl.Close()
	}()
	return kl
}

// Params 装配参数。
type Params struct {
	Service *registry.Service
	Config  config.Config
	Logger  *slog.Logger
	Metrics *Metrics
	Version string
}

// Server HTTP 服务。
type Server struct {
	svc     *registry.Service
	cfg     config.Config
	log     *slog.Logger
	metrics *Metrics
	version string
	hub     *signaling.Hub // M3 信令（signaling.enabled=false 时为 nil）

	resolveLim *ratelimit.KeyedLimiter // 读路径(resolve/node 查询)
	writeLim   *ratelimit.KeyedLimiter // 写路径(register/announce/信道接入)
	adminLim   *ratelimit.KeyedLimiter // 管理端
}

// New 构造 Server。ctx 用于限流器/信令清扫协程的生命周期。
func New(ctx context.Context, p Params) *Server {
	log := p.Logger
	if log == nil {
		log = slog.Default()
	}
	m := p.Metrics
	if m == nil {
		m = NewMetrics()
	}
	var hub *signaling.Hub
	if p.Config.Signaling.Enabled {
		hub = signaling.NewHub(ctx, signaling.Config{
			SessionTTL:         p.Config.Signaling.SessionTTL,
			IdleTimeout:        p.Config.Signaling.IdleTimeout,
			HelloTimeout:       p.Config.Signaling.HelloTimeout,
			PingPeriod:         20 * time.Second,
			WriteWait:          10 * time.Second,
			MaxFrameBytes:      p.Config.Signaling.MaxFrameBytes,
			MaxSessionsPerNode: p.Config.Signaling.MaxSessionsPerNode,
			MaxTotalSessions:   p.Config.Signaling.MaxTotalSessions,
		}, p.Service, m)
	}
	return &Server{
		svc:        p.Service,
		cfg:        p.Config,
		log:        log,
		metrics:    m,
		version:    p.Version,
		hub:        hub,
		resolveLim: newKeyedLimiter(ctx, 1, 120), // resolve: 平均 1/s 突发 120
		writeLim:   newKeyedLimiter(ctx, 2, 120), // 写路径: 平均 2/s 突发 120
		adminLim:   newKeyedLimiter(ctx, 10, 60), // 管理端宽松
	}
}

// Handler 构建完整 HTTP 处理链。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)
	// /metrics 门禁(2026-10-05 审计 P3):配置了管理口令时同 adminGate 校验
	// (Prometheus 抓取侧配 Authorization: Bearer <FCB_P2P_ADMIN_PASSWORD>);
	// 未配置口令保持开放(默认部署兼容,文档声明)。
	var metricsHandler http.Handler = promHandler(s.metrics.reg)
	if s.cfg.Admin.Password != "" {
		metricsHandler = s.adminGate(metricsHandler.ServeHTTP)
	}
	mux.Handle("GET /metrics", metricsHandler)

	s.route(mux, "POST /v1/nodes/register", "register", s.writeLim, s.handleRegister)
	s.route(mux, "POST /v1/nodes/heartbeat", "heartbeat", s.writeLim, s.handleRegister) // 与 register 同语义(幂等 upsert)
	s.route(mux, "GET /v1/nodes/{id}", "node_get", s.resolveLim, s.handleGetNode)
	s.route(mux, "DELETE /v1/nodes/{id}", "node_delete", s.writeLim, s.handleDeregister)

	s.route(mux, "POST /v1/announces", "announce", s.writeLim, s.handleAnnounce)
	s.route(mux, "DELETE /v1/announces/{hash}", "announce_delete", s.writeLim, s.handleRevoke)
	s.route(mux, "GET /v1/resolve/{hash}", "resolve", s.resolveLim, s.handleResolve)

	s.route(mux, "GET /v1/admin/stats", "admin_stats", s.adminLim, s.adminGate(s.handleAdminStats))
	s.route(mux, "GET /v1/admin/nodes", "admin_nodes", s.adminLim, s.adminGate(s.handleAdminNodes))
	s.route(mux, "GET /v1/admin/announces", "admin_announces", s.adminLim, s.adminGate(s.handleAdminAnnounces))
	s.route(mux, "DELETE /v1/admin/nodes/{id}", "admin_node_delete", s.adminLim, s.adminGate(s.handleAdminDeleteNode))

	// M3 信令信道（signaling.enabled=false 时不注册）
	if s.hub != nil {
		s.route(mux, "GET /v1/channel/{hash}", "channel", s.writeLim, s.hub.Handler())
	}

	return recoverMW(s.log, requestLogMW(s.log, mux))
}

// route 注册路由:指标(外层,含 429)→ 限流(内层)→ 业务 handler。
func (s *Server) route(mux *http.ServeMux, pattern, name string, l *ratelimit.KeyedLimiter, h http.HandlerFunc) {
	mux.HandleFunc(pattern, s.withMetrics(name, s.withLimit(l, h)))
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var in registry.RegisterInput
	if !s.decode(w, r, &in) {
		return
	}
	node, err := s.svc.RegisterNode(r.Context(), in, s.clientIP(r))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":    node.ID,
		"url":        node.URL,
		"expires_at": node.ExpiresAt.Unix(),
	})
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	node, err := s.svc.GetNode(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id": node.ID, "url": node.URL, "name": node.Name,
		"version": node.Version, "caps": node.Caps, "expires_at": node.ExpiresAt.Unix(),
	})
}

func (s *Server) handleDeregister(w http.ResponseWriter, r *http.Request) {
	var in registry.RevokeInput
	if !s.decode(w, r, &in) {
		return
	}
	if err := s.svc.DeregisterNode(r.Context(), in); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAnnounce(w http.ResponseWriter, r *http.Request) {
	var in registry.AnnounceInput
	if !s.decode(w, r, &in) {
		return
	}
	a, err := s.svc.Announce(r.Context(), in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code_hash": a.CodeHash, "node_id": a.NodeID, "expires_at": a.ExpiresAt.Unix(),
	})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var in registry.RevokeInput
	if !s.decode(w, r, &in) {
		return
	}
	in.CodeHash = r.PathValue("hash")
	if err := s.svc.RevokeAnnounce(r.Context(), in); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	a, node, err := s.svc.Resolve(r.Context(), r.PathValue("hash"))
	if err != nil {
		s.metrics.resolveTotal.WithLabelValues("miss").Inc()
		s.writeErr(w, err)
		return
	}
	s.metrics.resolveTotal.WithLabelValues("hit").Inc()
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id": node.ID, "url": node.URL, "name": node.Name,
		"expires_at": a.ExpiresAt.Unix(), "size_hint": a.SizeHint,
	})
}

// adminGate 管理端口令门:未配置口令时整体禁用。
func (s *Server) adminGate(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pw := s.cfg.Admin.Password
		if pw == "" {
			writeErr(w, http.StatusForbidden, errors.New("admin 未启用(未配置 FCB_P2P_ADMIN_PASSWORD)"))
			return
		}
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) || !secureEqual(strings.TrimPrefix(auth, prefix), pw) {
			writeErr(w, http.StatusUnauthorized, errors.New("admin 口令错误"))
			return
		}
		h(w, r)
	}
}

func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	nodes, announces, err := s.svc.Stats(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": nodes, "announces": announces, "version": s.version,
	})
}

func (s *Server) handleAdminNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.svc.ListNodes(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes})
}

func (s *Server) handleAdminAnnounces(w http.ResponseWriter, r *http.Request) {
	announces, err := s.svc.ListAnnounces(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"announces": announces})
}

func (s *Server) handleAdminDeleteNode(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.AdminDeleteNode(r.Context(), r.PathValue("id")); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- 公共小件 ----

// decode 读取并反序列化 JSON 请求体(限制大小)。
func (s *Server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("请求体非法: %v", err))
		return false
	}
	return true
}

// writeErr 按哨兵错误映射 HTTP 状态码。
func (s *Server) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, registry.ErrInvalidRequest), errors.Is(err, registry.ErrStaleTimestamp):
		writeErr(w, http.StatusBadRequest, err)
	case errors.Is(err, registry.ErrUnauthorized), errors.Is(err, registry.ErrBadSignature):
		writeErr(w, http.StatusUnauthorized, err)
	case errors.Is(err, registry.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, registry.ErrConflict):
		writeErr(w, http.StatusConflict, err)
	case errors.Is(err, registry.ErrQuotaExceeded):
		writeErr(w, http.StatusTooManyRequests, err)
	default:
		s.log.Error("内部错误", "err", err)
		writeErr(w, http.StatusInternalServerError, errors.New("内部错误"))
	}
}

// clientIP 取客户端 IP。BehindProxy=true 时信任 X-Forwarded-For 首段。
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.Server.BehindProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
