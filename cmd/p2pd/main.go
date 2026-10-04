// p2pd — FilesCodeBox P2P 联邦注册中心。
//
// 单进程单二进制:节点租约注册/心跳、口令公告路由(SHA-256 哈希,不接触明文)、
// 管理端与 Prometheus 指标。M3 起追加 WS 信令与加密中继。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/filescodebox/p2p/internal/config"
	"github.com/filescodebox/p2p/internal/registry"
	"github.com/filescodebox/p2p/internal/server"
	"github.com/filescodebox/p2p/internal/store/memory"
)

// 构建信息,由 -ldflags -X 注入。
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

const sweepInterval = 30 * time.Second

func main() {
	configPath := flag.String("config", "", "配置文件路径(缺省依次找 CONFIG_PATH env / ./configs/config.yaml,均无则用内置默认)")
	showVersion := flag.Bool("version", false, "打印版本后退出")
	flag.Parse()

	if *showVersion {
		fmt.Printf("p2pd %s (commit %s, built %s)\n", Version, Commit, BuildTime)
		return
	}
	path := resolveConfigPath(*configPath)

	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.Log.Level)
	slog.SetDefault(logger)

	svc := registry.New(registry.Params{
		Store:          memory.New(),
		RequireToken:   registrationToken(cfg),
		MinNodeTTL:     cfg.Registration.MinNodeTTL,
		MaxNodeTTL:     cfg.Registration.MaxNodeTTL,
		MaxAnnounces:   cfg.Announce.MaxPerNode,
		MaxAnnounceTTL: cfg.Announce.MaxTTL,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(ctx, server.Params{
		Service: svc,
		Config:  *cfg,
		Logger:  logger,
		Version: Version,
	})

	// 清扫循环:物理回收过期租约/公告并刷新活跃量指标。
	go func() {
		t := time.NewTicker(sweepInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				nodes, announces := svc.Sweep(context.Background())
				if nodes > 0 || announces > 0 {
					logger.Info("清扫完成", "nodes_expired", nodes, "announces_expired", announces)
				}
			}
		}
	}()

	httpSrv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      srv.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	logger.Info("p2pd 已启动",
		"version", Version, "commit", Commit,
		"port", cfg.Server.Port,
		"registration_mode", cfg.Registration.Mode,
		"admin_enabled", cfg.Admin.Password != "",
		"relay", "M3 未实现",
	)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil {
			logger.Error("服务器异常退出", "err", err)
			os.Exit(1)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("关闭未完全收尾", "err", err)
	}
	logger.Info("p2pd 已退出")
}

// resolveConfigPath 解析配置路径:显式指定 > CONFIG_PATH > 默认位置(存在才用)。
func resolveConfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if p := os.Getenv("CONFIG_PATH"); p != "" {
		return p
	}
	const def = "./configs/config.yaml"
	if _, err := os.Stat(def); err == nil {
		return def
	}
	return ""
}

func registrationToken(cfg *config.Config) string {
	if cfg.Registration.Mode == "token" {
		return cfg.Registration.Token
	}
	return ""
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv}))
}
