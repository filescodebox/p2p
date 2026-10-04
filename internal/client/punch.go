package client

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/filescodebox/p2p/internal/reflect"
)

// ---- 候选交换与 UDP 同时开洞 ----

// candInfo 打洞候选与传输凭据（经 PAKE 派生密钥加密后过信令信道）。
type candInfo struct {
	UDPPublic  string   `json:"udp_public"` // 反射器观察到的映射地址
	UDPLAN     []string `json:"udp_lan"`    // 本机各网卡 IPv4:port
	CertFP     string   `json:"cert_fp"`    // 临时证书指纹 hex(sha256(DER))
	RelayToken string   `json:"relay_token"`
}

// sealOpen k_cand 加解密助手（nonce 前缀格式,与 wire 一致的思路）。
func seal(key [32]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func open(key [32]byte, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	if len(data) < chacha20poly1305.NonceSize+aead.Overhead() {
		return nil, errors.New("密文过短")
	}
	nonce, ct := data[:chacha20poly1305.NonceSize], data[chacha20poly1305.NonceSize:]
	return aead.Open(nil, nonce, ct, nil)
}

// reflectOwn 向 registry 同端口的 UDP 反射器查询本套接字的公网映射地址。
func reflectOwn(sock *net.UDPConn, registryBase string) *net.UDPAddr {
	addr, err := reflect.Query(sock, hostOf(registryBase), time.Second)
	if err != nil {
		return nil // 反射失败不致命:退化为仅 LAN 候选+中继
	}
	return addr
}

// lanCandidates 枚举本机 IPv4 地址与套接字端口的组合。
func lanCandidates(sock *net.UDPConn) []string {
	port := sock.LocalAddr().(*net.UDPAddr).Port
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, net.JoinHostPort(ip4.String(), fmt.Sprint(port)))
		}
	}
	return out
}

// punch UDP 同时开洞：双方互发加密探针，任一候选路径收到可解密包即成功。
// 返回验证过的对端地址（从本套接字视角）。budget 内未成即失败（走中继）。
func punch(sock *net.UDPConn, peer *candInfo, k [32]byte, budget time.Duration) (*net.UDPAddr, error) {
	aead, err := chacha20poly1305.New(k[:])
	if err != nil {
		return nil, err
	}
	probe := func() ([]byte, error) {
		nonce := make([]byte, chacha20poly1305.NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		return aead.Seal(nonce, nonce, []byte("fcb-punch-v1"), nil), nil
	}

	var targets []*net.UDPAddr
	add := func(s string) {
		if s == "" {
			return
		}
		if a, err := net.ResolveUDPAddr("udp", s); err == nil {
			targets = append(targets, a)
		}
	}
	add(peer.UDPPublic)
	for _, l := range peer.UDPLAN {
		add(l)
	}
	if len(targets) == 0 {
		return nil, errors.New("对端无可用候选")
	}

	stop := make(chan struct{})
	var sendWG sync.WaitGroup
	sendWG.Add(1)
	go func() { // 探针发送循环(对每个候选,周期性同时开洞)
		defer sendWG.Done()
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				pkt, err := probe()
				if err != nil {
					return
				}
				for _, tgt := range targets {
					_, _ = sock.WriteToUDP(pkt, tgt)
				}
			}
		}
	}()
	defer func() { close(stop); sendWG.Wait() }()

	_ = sock.SetReadDeadline(time.Now().Add(budget))
	buf := make([]byte, 128)
	for {
		n, raddr, err := sock.ReadFromUDP(buf)
		if err != nil {
			return nil, errors.New("打洞失败(对端不可直连)")
		}
		// 只认可解密的探针=对端身份确认(防第三方注入)
		if _, err := aead.Open(nil, buf[:chacha20poly1305.NonceSize], buf[chacha20poly1305.NonceSize:n], nil); err == nil {
			return raddr, nil
		}
	}
}

// hostOf 基址取 host[:port]。
func hostOf(base string) string {
	b := trimRight(base)
	b = strings.TrimPrefix(b, "https://")
	b = strings.TrimPrefix(b, "http://")
	if i := strings.Index(b, "/"); i >= 0 {
		b = b[:i]
	}
	return b
}

// exchangeCandidates 双方互换候选（PAKE 派生密钥加密——明文候选可被注入劫持）。
func exchangeCandidates(ch *channel, k [32]byte, own *candInfo) (*candInfo, error) {
	plain, err := json.Marshal(own)
	if err != nil {
		return nil, err
	}
	boxed, err := seal(k, plain)
	if err != nil {
		return nil, err
	}
	if err := ch.send(boxed); err != nil {
		return nil, fmt.Errorf("候选发送: %w", err)
	}
	boxedPeer, err := ch.recv()
	if err != nil {
		return nil, fmt.Errorf("候选接收: %w", err)
	}
	plainPeer, err := open(k, boxedPeer)
	if err != nil {
		return nil, fmt.Errorf("候选解密失败(对端口令不一致?): %w", err)
	}
	var peer candInfo
	if err := json.Unmarshal(plainPeer, &peer); err != nil {
		return nil, fmt.Errorf("候选解析: %w", err)
	}
	return &peer, nil
}
