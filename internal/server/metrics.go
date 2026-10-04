package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics p2pd 指标集。独立 Registry,避免测试间全局污染。
type Metrics struct {
	reg *prometheus.Registry

	httpRequests      *prometheus.CounterVec // method, route, code
	resolveTotal      *prometheus.CounterVec // result: hit|miss
	rateLimited       prometheus.Counter
	nodesActive       prometheus.Gauge
	announcesGauge    prometheus.Gauge
	signalingSessions prometheus.Gauge
	signalingJoins    *prometheus.CounterVec // result: waiting|paired|busy|rejected
}

// NewMetrics 构造指标集。
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{reg: reg}
	f := promauto.With(reg)
	m.httpRequests = f.NewCounterVec(prometheus.CounterOpts{
		Name: "p2p_http_requests_total", Help: "HTTP 请求计数(按路由静态名)",
	}, []string{"method", "route", "code"})
	m.resolveTotal = f.NewCounterVec(prometheus.CounterOpts{
		Name: "p2p_resolve_total", Help: "口令解析计数",
	}, []string{"result"})
	m.rateLimited = f.NewCounter(prometheus.CounterOpts{
		Name: "p2p_rate_limited_total", Help: "限流拦截计数",
	})
	m.nodesActive = f.NewGauge(prometheus.GaugeOpts{
		Name: "p2p_nodes_active", Help: "当前有效节点租约数",
	})
	m.announcesGauge = f.NewGauge(prometheus.GaugeOpts{
		Name: "p2p_announces_active", Help: "当前有效公告数",
	})
	m.signalingSessions = f.NewGauge(prometheus.GaugeOpts{
		Name: "p2p_signaling_sessions_active", Help: "当前活跃信令会话数(含等待配对)",
	})
	m.signalingJoins = f.NewCounterVec(prometheus.CounterOpts{
		Name: "p2p_signaling_joins_total", Help: "信令信道接入计数",
	}, []string{"result"})
	return m
}

// SignalingSessions 实现 signaling.Metrics（会话仪表增减）。
func (m *Metrics) SignalingSessions(delta int) { m.signalingSessions.Add(float64(delta)) }

// SignalingJoin 实现 signaling.Metrics（接入计数）。
func (m *Metrics) SignalingJoin(result string) { m.signalingJoins.WithLabelValues(result).Inc() }

// SetGauges 由清扫循环周期刷新活跃量仪表。
func (m *Metrics) SetGauges(nodes, announces int) {
	m.nodesActive.Set(float64(nodes))
	m.announcesGauge.Set(float64(announces))
}

func promHandler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
