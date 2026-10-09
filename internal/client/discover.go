// 注册中心发现与多源 failover:
//   - 单基址照旧;--registry 传裸域名(无 scheme/无端口/非 IP)时走 DNS 发现:
//     SRV _p2pc._tcp.<domain> 优先,回落 A/AAAA :12346(Bitcoin DNS seed 同构——
//     官方公共节点以 DNS 列表引导,信任面最小)。
//   - 多注册中心:PB_P2P_REGISTRIES(逗号分隔)与 --registry 合并去重,按
//     rendezvous hashing(SHA-256(口令|基址))对每个口令确定性排序——两端同表
//     同序,公告/解析/信道自然汇聚到同一节点,零协调分片;失败顺延下一节点。
package client

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"sort"
	"strings"
)

const defaultRegistryPort = "12346"

// registryChain 返回按 HRW 排序的注册中心基址链(去重;DNS 展开仅在裸域名时)。
func (c *Client) registryChain(code string) []string {
	list := []string{c.opt.Registry}
	list = append(list, c.opt.Registries...)
	if env := os.Getenv("PB_P2P_REGISTRIES"); env != "" {
		list = append(list, strings.Split(env, ",")...)
	}
	var out []string
	seen := map[string]bool{}
	for _, raw := range list {
		for _, b := range expandRegistry(strings.TrimSpace(raw)) {
			if b != "" && !seen[b] {
				seen[b] = true
				out = append(out, b)
			}
		}
	}
	hrwOrder(out, code)
	return out
}

// expandRegistry 单基址规范化:裸域名走 DNS(SRV→A/AAAA),其余原样(补 scheme)。
func expandRegistry(raw string) []string {
	if raw == "" {
		return nil
	}
	if strings.Contains(raw, "://") {
		return []string{strings.TrimRight(raw, "/")}
	}
	host := raw
	// 含端口或为 IP 字面量:非发现语义,补 scheme 即可
	if h, _, err := net.SplitHostPort(raw); err == nil && net.ParseIP(h) != nil {
		return []string{"http://" + raw}
	}
	if net.ParseIP(host) != nil {
		return []string{"http://" + host + ":" + defaultRegistryPort}
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h // host:port 形式的域名:只做 A/AAAA
		_, _, _ = net.SplitHostPort(raw)
		if _, err := net.LookupHost(host); err != nil {
			return nil
		}
		return []string{"http://" + raw}
	}
	// 裸域名:SRV 优先
	_, srvs, err := net.LookupSRV("p2pc", "tcp", host)
	if err == nil && len(srvs) > 0 {
		var out []string
		for _, s := range srvs {
			t := strings.TrimSuffix(s.Target, ".")
			if t != "" {
				out = append(out, "http://"+net.JoinHostPort(t, itoa(int(s.Port))))
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	if _, err := net.LookupHost(host); err != nil {
		return nil // 域名不可解析:剔除
	}
	return []string{"http://" + net.JoinHostPort(host, defaultRegistryPort)}
}

// hrwOrder rendezvous hashing 就地排序:score=SHA-256(口令|基址),降序。
// 同表同口令 ⇒ 同序(两端零协调汇聚同一节点)。
func hrwOrder(bases []string, code string) {
	type scored struct {
		s [32]byte
		i int
	}
	sc := make([]scored, len(bases))
	for i, b := range bases {
		sum := sha256.Sum256([]byte(code + "|" + b))
		sc[i] = scored{s: sum, i: i}
	}
	sort.Slice(sc, func(a, b int) bool {
		return hex.EncodeToString(sc[a].s[:]) > hex.EncodeToString(sc[b].s[:])
	})
	ordered := make([]string, len(bases))
	for i, v := range sc {
		ordered[i] = bases[v.i]
	}
	copy(bases, ordered)
}

func itoa(n int) string { return strings.TrimSpace(strings.Join([]string{fmtInt(n)}, "")) }

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
