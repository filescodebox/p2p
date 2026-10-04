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
	Log          Log
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
	return nil
}
