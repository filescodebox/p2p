// Package config 加载 p2pd 配置。
//
// 优先级(高→低): FCB_P2P_* 环境变量 > 配置文件(--config / CONFIG_PATH) > 内置默认。
// 所有键均有默认值,配置文件可省略。
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config p2pd 全量配置。
type Config struct {
	Server       Server
	Registration Registration
	Announce     Announce
	Admin        Admin
	Signaling    Signaling
	Relay        Relay
	Reflector    Reflector
	Log          Log
}

// Relay 加密中继配置（M3 打洞失败的兜底;默认整机关闭）。
type Relay struct {
	// Enabled 总开关（默认 false——不存在可被滥用的开放代理）。
	// env: FCB_P2P_RELAY_ENABLED
	Enabled bool
	// Port 中继 TCP 端口。env: FCB_P2P_RELAY_PORT
	Port int
	// MbpsPerChannel 单信道带宽上限（Mbps,0=不限）。env: FCB_P2P_RELAY_MBPS
	MbpsPerChannel int64
}

// Reflector UDP 地址反射器（打洞前提;与 HTTP 同端口,默认开）。
type Reflector struct {
	// Enabled 总开关。env: FCB_P2P_REFLECTOR_ENABLED
	Enabled bool
}

// Signaling WS 信令信道配置（M3 设备直传；默认开——准入由节点签名把守，
// 关闭只影响直传配对，不影响注册/公告/解析）。
type Signaling struct {
	// Enabled 总开关。env: FCB_P2P_SIGNALING_ENABLED
	Enabled bool
	// SessionTTL 会话最长生命周期（含等待配对）。env: FCB_P2P_SIGNALING_SESSION_TTL
	SessionTTL time.Duration
	// IdleTimeout 连接空闲上限（pong 与数据帧均续期）。env: FCB_P2P_SIGNALING_IDLE_TIMEOUT
	IdleTimeout time.Duration
	// HelloTimeout 接入后交 hello 的时限。env: FCB_P2P_SIGNALING_HELLO_TIMEOUT
	HelloTimeout time.Duration
	// MaxFrameBytes data 帧负载上限（字节）。env: FCB_P2P_SIGNALING_MAX_FRAME_BYTES
	MaxFrameBytes int
	// MaxSessionsPerNode 单节点并发会话上限。env: FCB_P2P_SIGNALING_MAX_PER_NODE
	MaxSessionsPerNode int
	// MaxTotalSessions 全局并发会话上限。env: FCB_P2P_SIGNALING_MAX_TOTAL
	MaxTotalSessions int
}

// Server HTTP 服务参数。
type Server struct {
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	// BehindProxy 为 true 时从 X-Forwarded-For 取客户端 IP(反代部署,如 nginx/openresty);
	// 默认 false,直取 RemoteAddr,防止伪造头绕过限流。
	BehindProxy bool
}

// Registration 节点注册策略。
type Registration struct {
	// Mode: open(开放注册) | token(邀请制,须携带共享注册密钥)。
	Mode  string
	Token string
	// MinNodeTTL/MaxNodeTTL 限制节点租约时长,节点须周期心跳续租。
	MinNodeTTL time.Duration
	MaxNodeTTL time.Duration
}

// Announce 公告(口令路由)配额。
type Announce struct {
	MaxPerNode int
	MaxTTL     time.Duration
}

// Admin 管理端点。Password 为空时管理 API 整体禁用(403)。
// 推荐仅经环境变量 FCB_P2P_ADMIN_PASSWORD 注入,不落配置文件。
type Admin struct {
	Password string
}

// Log 日志。
type Log struct {
	Level string
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.port", 12346)
	v.SetDefault("server.read_timeout", 10*time.Second)
	v.SetDefault("server.write_timeout", 30*time.Second)
	v.SetDefault("server.idle_timeout", 120*time.Second)
	v.SetDefault("server.behind_proxy", false)
	v.SetDefault("registration.mode", "open")
	v.SetDefault("registration.token", "")
	v.SetDefault("registration.min_node_ttl", 5*time.Minute)
	v.SetDefault("registration.max_node_ttl", 24*time.Hour)
	v.SetDefault("announce.max_per_node", 1000)
	v.SetDefault("announce.max_ttl", 168*time.Hour)
	v.SetDefault("admin.password", "")
	v.SetDefault("log.level", "info")
	// 信令信道（M3；准入由节点签名把守，默认开）
	v.SetDefault("signaling.enabled", true)
	v.SetDefault("signaling.session_ttl", 10*time.Minute)
	v.SetDefault("signaling.idle_timeout", 2*time.Minute)
	v.SetDefault("signaling.hello_timeout", 10*time.Second)
	v.SetDefault("signaling.ping_period", 20*time.Second)
	v.SetDefault("signaling.write_wait", 10*time.Second)
	v.SetDefault("signaling.max_frame_bytes", 16384)
	v.SetDefault("signaling.max_sessions_per_node", 8)
	v.SetDefault("signaling.max_total_sessions", 1024)
	// 中继(M3 兜底;默认关)+UDP 反射器(打洞前提;默认开)
	v.SetDefault("relay.enabled", false)
	v.SetDefault("relay.port", 12347)
	v.SetDefault("relay.mbps_per_channel", 10)
	v.SetDefault("reflector.enabled", true)
}

// Load 读取配置。path 为空时仅用默认值+环境变量。
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetEnvPrefix("FCB_P2P")
	v.AutomaticEnv()
	// server.port → FCB_P2P_SERVER_PORT
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	setDefaults(v)

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("读取配置 %s: %w", path, err)
		}
	}

	c := &Config{
		Server: Server{
			Port:         v.GetInt("server.port"),
			ReadTimeout:  v.GetDuration("server.read_timeout"),
			WriteTimeout: v.GetDuration("server.write_timeout"),
			IdleTimeout:  v.GetDuration("server.idle_timeout"),
			BehindProxy:  v.GetBool("server.behind_proxy"),
		},
		Registration: Registration{
			Mode:       v.GetString("registration.mode"),
			Token:      v.GetString("registration.token"),
			MinNodeTTL: v.GetDuration("registration.min_node_ttl"),
			MaxNodeTTL: v.GetDuration("registration.max_node_ttl"),
		},
		Announce: Announce{
			MaxPerNode: v.GetInt("announce.max_per_node"),
			MaxTTL:     v.GetDuration("announce.max_ttl"),
		},
		Admin: Admin{
			Password: v.GetString("admin.password"),
		},
		Signaling: Signaling{
			Enabled:            v.GetBool("signaling.enabled"),
			SessionTTL:         v.GetDuration("signaling.session_ttl"),
			IdleTimeout:        v.GetDuration("signaling.idle_timeout"),
			HelloTimeout:       v.GetDuration("signaling.hello_timeout"),
			MaxFrameBytes:      v.GetInt("signaling.max_frame_bytes"),
			MaxSessionsPerNode: v.GetInt("signaling.max_sessions_per_node"),
			MaxTotalSessions:   v.GetInt("signaling.max_total_sessions"),
		},
		Relay: Relay{
			Enabled:        v.GetBool("relay.enabled"),
			Port:           v.GetInt("relay.port"),
			MbpsPerChannel: v.GetInt64("relay.mbps_per_channel"),
		},
		Reflector: Reflector{
			Enabled: v.GetBool("reflector.enabled"),
		},
		Log: Log{
			Level: v.GetString("log.level"),
		},
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port 非法: %d", c.Server.Port)
	}
	switch c.Registration.Mode {
	case "open", "token":
	case "":
		c.Registration.Mode = "open"
	default:
		return fmt.Errorf("registration.mode 仅支持 open|token,当前: %q", c.Registration.Mode)
	}
	if c.Registration.Mode == "token" && c.Registration.Token == "" {
		return fmt.Errorf("registration.mode=token 时必须设置 registration.token(或 FCB_P2P_REGISTRATION_TOKEN)")
	}
	if c.Registration.MinNodeTTL <= 0 || c.Registration.MaxNodeTTL < c.Registration.MinNodeTTL {
		return fmt.Errorf("node TTL 区间非法: min=%s max=%s", c.Registration.MinNodeTTL, c.Registration.MaxNodeTTL)
	}
	if c.Announce.MaxPerNode < 1 || c.Announce.MaxTTL <= 0 {
		return fmt.Errorf("announce 配额非法: max_per_node=%d max_ttl=%s", c.Announce.MaxPerNode, c.Announce.MaxTTL)
	}
	if c.Signaling.Enabled {
		if c.Signaling.SessionTTL <= 0 || c.Signaling.IdleTimeout <= 0 || c.Signaling.HelloTimeout <= 0 {
			return fmt.Errorf("signaling 时长参数非法: ttl=%s idle=%s hello=%s",
				c.Signaling.SessionTTL, c.Signaling.IdleTimeout, c.Signaling.HelloTimeout)
		}
		if c.Signaling.MaxFrameBytes < 1024 || c.Signaling.MaxFrameBytes > 1<<20 {
			return fmt.Errorf("signaling.max_frame_bytes 须在 [1KB,1MB],当前: %d", c.Signaling.MaxFrameBytes)
		}
		if c.Signaling.MaxSessionsPerNode < 1 || c.Signaling.MaxTotalSessions < 1 {
			return fmt.Errorf("signaling 会话上限非法: per_node=%d total=%d",
				c.Signaling.MaxSessionsPerNode, c.Signaling.MaxTotalSessions)
		}
	}
	if c.Relay.Enabled {
		if c.Relay.Port < 1 || c.Relay.Port > 65535 {
			return fmt.Errorf("relay.port 非法: %d", c.Relay.Port)
		}
		if c.Relay.MbpsPerChannel < 0 {
			return fmt.Errorf("relay.mbps_per_channel 非法: %d", c.Relay.MbpsPerChannel)
		}
	}
	return nil
}
