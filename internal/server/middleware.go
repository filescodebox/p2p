package server

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/filescodebox/p2p/internal/limiter"
)

var (
	errInternal    = errors.New("内部错误")
	errRateLimited = errors.New("请求过于频繁")
)

// recoverMW panic 兜底:记日志并回 500,防止单请求打挂进程。
func recoverMW(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Error("panic 已拦截", "method", r.Method, "path", r.URL.Path, "panic", rec)
				writeErr(w, http.StatusInternalServerError, errInternal)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestLogMW 请求访问日志(方法/路径/状态/耗时)。
func requestLogMW(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		log.Info("http", "method", r.Method, "path", r.URL.Path,
			"status", rec.status, "dur_ms", time.Since(start).Milliseconds())
	})
}

// statusRecorder 捕获响应状态码。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// statusLabel 归一化状态码标签(2xx/4xx/5xx 细分到百位,控基数)。
func (s *statusRecorder) statusLabel() string {
	switch {
	case s.status < 300:
		return "2xx"
	case s.status < 400:
		return "3xx"
	case s.status < 500:
		return "4xx"
	default:
		return "5xx"
	}
}

// withLimit 令牌桶限流包装;超限回 429。
func (s *Server) withLimit(l *limiter.Limiter, h http.HandlerFunc) http.HandlerFunc {
	if l == nil {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(s.clientIP(r)) {
			s.metrics.rateLimited.Inc()
			writeErr(w, http.StatusTooManyRequests, errRateLimited)
			return
		}
		h(w, r)
	}
}

// withMetrics 路由粒度请求计数(route 用静态名,避免路径参数基数爆炸)。
func (s *Server) withMetrics(route string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h(rec, r)
		s.metrics.httpRequests.WithLabelValues(r.Method, route, rec.statusLabel()).Inc()
	}
}

// secureEqual 恒时比较,防管理口令时序侧信道。
func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
