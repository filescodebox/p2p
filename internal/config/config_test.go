package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSplitProxies(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"10.0.0.0/8", []string{"10.0.0.0/8"}},
		{"10.0.0.0/8,172.16.0.0/12", []string{"10.0.0.0/8", "172.16.0.0/12"}},
		{" 10.0.0.0/8 , 172.16.0.0/12 ", []string{"10.0.0.0/8", "172.16.0.0/12"}},
		// YAML 列表经 GetString 的形态
		{"[10.0.0.0/8 172.16.0.0/12]", []string{"10.0.0.0/8", "172.16.0.0/12"}},
		{",,", nil},
	}
	for _, c := range cases {
		got := splitProxies(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("splitProxies(%q)=%v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("splitProxies(%q)=%v, want %v", c.in, got, c.want)
			}
		}
	}
}

func TestLoadUnknownKeyWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "server:\n  port: 12346\n  prot: 12345\n" // prot=拼写错误
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Warnings) == 0 {
		t.Fatal("拼写错误的键应产生告警")
	}
	found := false
	for _, w := range c.Warnings {
		if strings.Contains(w, "server.prot") {
			found = true
		}
	}
	if !found {
		t.Fatalf("告警应点名 server.prot: %v", c.Warnings)
	}
	if c.Server.Port != 12346 {
		t.Fatalf("合法键不受影响: %d", c.Server.Port)
	}
}

func TestLoadCapacityKeysReachStructs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// 2026-10-09 前这两个键 defaults 有值但 Load 漏读(死配置)
	body := "registration:\n  max_nodes: 123\nannounce:\n  max_total: 456\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Registration.MaxNodes != 123 || c.Announce.MaxTotal != 456 {
		t.Fatalf("容量键未生效: max_nodes=%d max_total=%d", c.Registration.MaxNodes, c.Announce.MaxTotal)
	}
}

func TestTLSValidation(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	c.Server.TLSCert = "/tmp/a.pem"
	if err := c.validate(); err == nil {
		t.Fatal("只配证书不配私钥应报错")
	}
	c.Server.TLSKey = "/tmp/a.key"
	if err := c.validate(); err != nil {
		t.Fatalf("成对配置应通过: %v", err)
	}
}

func TestRelayCapacityValidation(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	c.Relay.Enabled = true
	c.Relay.MaxConnsPerIP = -1
	if err := c.validate(); err == nil {
		t.Fatal("负容量应报错")
	}
	c.Relay.MaxConnsPerIP = 0 // 0=用内置默认,合法
	c.Relay.WaitingTimeout = 45 * time.Second
	if err := c.validate(); err != nil {
		t.Fatalf("合法容量应通过: %v", err)
	}
}
