package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/filescodebox/p2p/internal/wire"
)

// Options 客户端参数。
type Options struct {
	Registry string // p2pd 基址,如 http://127.0.0.1:12346
	// NodeKeyPath 节点身份密钥（缺省 ~/.fcb-p2p/node.key）
	NodeKeyPath string
	// RelayAddr 中继地址（缺省 registry host + :12347）
	RelayAddr string
	// DisablePunch 跳过打洞直接走中继（测试与强制兜底用）
	DisablePunch bool
	// PunchBudget 打洞预算（默认 4s）
	PunchBudget time.Duration
	// Quiet 关闭过程日志
	Quiet bool
}

// DefaultNodeKeyPath 默认密钥位置（用户缓存目录）。
func DefaultNodeKeyPath() string {
	base, err := os.UserCacheDir()
	if err != nil {
		return "fcb-p2p-node.key"
	}
	return filepath.Join(base, "fcb-p2p", "node.key")
}

// Client 直传客户端。
type Client struct {
	opt Options
	id  *nodeIdentity
	log *slog.Logger
	reg *registryAPI
}

// New 构造客户端（加载/生成节点身份密钥）。
func New(opt Options) (*Client, error) {
	if opt.Registry == "" {
		return nil, fmt.Errorf("registry 地址必填")
	}
	if opt.NodeKeyPath == "" {
		opt.NodeKeyPath = DefaultNodeKeyPath()
	}
	if opt.PunchBudget <= 0 {
		opt.PunchBudget = 4 * time.Second
	}
	id, err := newNodeIdentity(opt.NodeKeyPath)
	if err != nil {
		return nil, err
	}
	log := slog.Default()
	if opt.Quiet {
		log = slog.New(discardHandler{})
	}
	return &Client{opt: opt, id: id, log: log, reg: newRegistryAPI(opt.Registry)}, nil
}

// codeAlphabet Crockford base32（去 I/L/O/U 歧义）。
const codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTWXYZ"

// GenerateCode 生成 12 位强口令（3×4 分组,≈60bit 熵——远超联邦公告门槛）。
func GenerateCode() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	var sb strings.Builder
	for i, b := range raw {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(codeAlphabet[int(b)%len(codeAlphabet)])
	}
	return sb.String(), nil
}

func (c *Client) relayAddr() string {
	if c.opt.RelayAddr != "" {
		return c.opt.RelayAddr
	}
	// registry 常带端口(http://host:22346),默认中继=同主机换 12347 端口
	// ——直接拼接会得到 host:22346:12347(215 部署实测踩坑)。
	host := hostOf(c.opt.Registry)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host + ":12347"
}

// setupNode 注册节点租约；返回 best-effort 注销函数。
func (c *Client) setupNode() func() {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "device"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.reg.register(ctx, c.id, hostname, time.Hour); err != nil {
		c.log.Warn("节点注册失败(继续尝试)", "err", err)
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.reg.deregister(ctx, c.id)
	}
}

// resolveRetry 解析带重试:500ms 间隔,超过 wait 后以最后一次错误返回。
func (c *Client) resolveRetry(code string, wait time.Duration) (string, error) {
	deadline := time.Now().Add(wait)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		id, err := c.reg.resolve(ctx, code)
		cancel()
		if err == nil {
			return id, nil
		}
		if !time.Now().After(deadline) {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		return "", fmt.Errorf("解析: %w", err)
	}
}

// progress 每 1MB 打一条进度日志。
func (c *Client) progress() func(got, total int64) {
	var last int64
	return func(got, total int64) {
		if got-last >= 1<<20 || got == total {
			last = got
			c.log.Info("传输进度", "got", got, "total", total)
		}
	}
}

// Send 发送单个文件。code 为空则自动生成；返回实际使用的口令。
func (c *Client) Send(path string, code string) (string, error) {
	if code == "" {
		var err error
		if code, err = GenerateCode(); err != nil {
			return "", err
		}
	}
	dereg := c.setupNode()
	defer dereg()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	expires := time.Now().Add(15 * time.Minute)
	if err := c.reg.announce(ctx, c.id, code, expires); err != nil {
		return "", fmt.Errorf("公告: %w", err)
	}
	c.log.Info("直传口令已就绪(等待对端)", "code", code)

	ch, err := joinChannel(c.opt.Registry, code, c.id, 10*time.Minute)
	if err != nil {
		return "", err
	}
	defer ch.close()
	c.log.Info("对端已接入,开始 PAKE")

	session, err := runPake([]byte(code), true, ch.exchange())
	if err != nil {
		return code, err
	}
	// 首个 AEAD 使用即口令正确性判定(错口令=密钥不一致=解密失败)

	cert, ownFP, err := sessionCert()
	if err != nil {
		return code, fmt.Errorf("会话证书: %w", err)
	}
	// 打洞与候选必须共用同一 UDP 套接字(反射地址才与打洞映射一致)
	// 显式 IPv4 单栈:双栈通配([::])下反射/打洞/QUIC 地址族混用(v4-mapped)
	// 会让 QUIC 流静默丢失——全程 IPv4 保持一致。
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return code, fmt.Errorf("UDP 套接字: %w", err)
	}
	own := buildCandidates(sock, c.opt.Registry)
	own.CertFP = ownFP
	peer, err := exchangeCandidates(ch, wire.DeriveKey(session, "cand"), own)
	if err != nil {
		_ = sock.Close()
		return code, err
	}

	w, cleanup, via, err := c.establish(sock, session, cert, peer.CertFP, peer, true)
	if err != nil {
		return code, err
	}
	defer cleanup()
	c.log.Info("传输通道建立", "via", via)

	if err := sendFile(w, path, c.progress()); err != nil {
		return code, err
	}
	c.log.Info("发送完成", "code", code)
	return code, nil
}

// Receive 接收文件到 dir。返回落盘路径。
func (c *Client) Receive(code, dir string) (string, error) {
	dereg := c.setupNode()
	defer dereg()

	// resolve 先行:钉定发送方身份(防信道被第三方抢入)。
	// 带短重试——接收方常先于发送方启动(发送方生成口令后才公告),
	// 首发 miss 属启动时序而非口令不存在。
	senderID, err := c.resolveRetry(code, 15*time.Second)
	if err != nil {
		return "", err
	}

	ch, err := joinChannel(c.opt.Registry, code, c.id, 10*time.Minute)
	if err != nil {
		return "", err
	}
	defer ch.close()
	if ch.peerID != senderID {
		return "", fmt.Errorf("身份核对失败: 信道对端 %s ≠ 公告节点 %s", ch.peerID, senderID)
	}
	c.log.Info("已配对且身份核对通过,开始 PAKE")

	session, err := runPake([]byte(code), false, ch.exchange())
	if err != nil {
		return "", err
	}

	cert, ownFP, err := sessionCert()
	if err != nil {
		return "", fmt.Errorf("会话证书: %w", err)
	}
	// 打洞与候选必须共用同一 UDP 套接字(反射地址才与打洞映射一致)
	// 显式 IPv4 单栈:双栈通配([::])下反射/打洞/QUIC 地址族混用(v4-mapped)
	// 会让 QUIC 流静默丢失——全程 IPv4 保持一致。
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return "", fmt.Errorf("UDP 套接字: %w", err)
	}
	own := buildCandidates(sock, c.opt.Registry)
	own.CertFP = ownFP
	peer, err := exchangeCandidates(ch, wire.DeriveKey(session, "cand"), own)
	if err != nil {
		_ = sock.Close()
		return "", err
	}

	w, cleanup, via, err := c.establish(sock, session, cert, peer.CertFP, peer, false)
	if err != nil {
		return "", err
	}
	defer cleanup()
	c.log.Info("传输通道建立", "via", via)

	out, err := recvFile(w, dir, c.progress())
	if err != nil {
		return "", err
	}
	c.log.Info("接收完成", "path", out)
	return out, nil
}

// establish 打洞(可跳过)→ QUIC over 打洞套接字;失败 → 中继 TCP。
// 成功走 QUIC 时套接字所有权移交 transport(cleanup 负责关闭);
// 打洞失败即当场关闭套接字回退中继。
func (c *Client) establish(sock *net.UDPConn, session []byte, cert tls.Certificate, peerFP string, peer *candInfo, isSender bool) (*wire.Conn, func(), string, error) {
	if !c.opt.DisablePunch && (peer.UDPPublic != "" || len(peer.UDPLAN) > 0) {
		remote, perr := punch(sock, peer, wire.DeriveKey(session, "cand"), c.opt.PunchBudget)
		if perr == nil {
			// punch 留下的读 deadline 必须清除,否则移交 QUIC 后到期会杀掉连接
			_ = sock.SetReadDeadline(time.Time{})
			w, cleanup, qerr := establishQUIC(sock, session, cert, peerFP, remote, isSender)
			if qerr == nil {
				return w, cleanup, "quic-direct", nil
			}
			c.log.Warn("QUIC 建立失败,回退中继", "err", qerr)
		} else {
			c.log.Info("打洞未成功,走中继")
		}
	} else if c.opt.DisablePunch {
		c.log.Info("已禁用打洞,直接走中继")
	} else {
		c.log.Info("对端无 UDP 候选,走中继")
	}
	_ = sock.Close() // 打洞路径未采用,套接字交还系统
	w, cleanup, rerr := establishRelay(session, c.relayAddr(), relayToken(session), isSender)
	if rerr != nil {
		return nil, nil, "", fmt.Errorf("打洞失败且中继不可用: %w", rerr)
	}
	return w, cleanup, "relay", nil
}

// ---- 小件 ----

// buildCandidates 用打洞套接字反射公网地址 + 枚举 LAN 候选。
func buildCandidates(sock *net.UDPConn, registryBase string) *candInfo {
	ci := &candInfo{UDPLAN: lanCandidates(sock)}
	if pub := reflectOwn(sock, registryBase); pub != nil {
		ci.UDPPublic = pub.String()
	}
	return ci
}

// discardHandler Quiet 模式的空日志处理器。
type discardHandler struct{}

func (discardHandler) Enabled(_ context.Context, _ slog.Level) bool  { return false }
func (discardHandler) Handle(_ context.Context, _ slog.Record) error { return nil }
func (h discardHandler) WithAttrs([]slog.Attr) slog.Handler          { return h }
func (h discardHandler) WithGroup(string) slog.Handler               { return h }
