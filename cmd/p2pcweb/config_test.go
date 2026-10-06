package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseXDGDownload(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "下载"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := parseXDGDownload("XDG_DOWNLOAD_DIR=\"$HOME/下载\"\n", home)
	if got != filepath.Join(home, "下载") {
		t.Fatalf("got %q", got)
	}
	// 目录不存在 → 视为无效
	if got := parseXDGDownload("XDG_DOWNLOAD_DIR=\"$HOME/不存在\"\n", home); got != "" {
		t.Fatalf("期望空, got %q", got)
	}
	// 无该键
	if got := parseXDGDownload("XDG_DOCUMENTS_DIR=\"$HOME/文档\"\n", home); got != "" {
		t.Fatalf("期望空, got %q", got)
	}
}

func TestSanitizeName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"报告 final.pdf", "报告 final.pdf"},
		{`a\b\c.txt`, "c.txt"},
		{"../etc/passwd", "passwd"},
		{"a/b/c.txt", "c.txt"},
		{"", "file"},
		{"..", "file"},
		{".hidden", "hidden"},
		{"bad:name*?.txt", "bad_name__.txt"},
		{"ctrl\x01char.txt", "ctrl_char.txt"},
	}
	for _, c := range cases {
		if got := sanitizeName(c.in); got != c.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// 超长截断保后缀（按 rune）
	long := strings.Repeat("长", 150) + ".pdf"
	got := []rune(sanitizeName(long))
	if len(got) != 100 || !strings.HasSuffix(string(got), ".pdf") {
		t.Errorf("超长处理异常: %d runes", len(got))
	}
}

func TestCfgStoreRoundtrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "p2pcweb.json")
	s := &cfgStore{p: p}
	if err := s.set(Config{ServerURL: "http://10.0.0.2", Registry: "http://r:12346"}); err != nil {
		t.Fatal(err)
	}
	loaded := newCfgStoreAt(p)
	if _, err := os.ReadFile(p); err != nil {
		t.Fatal(err)
	}
	got := loaded.get()
	if got.ServerURL != "http://10.0.0.2" || got.Registry != "http://r:12346" {
		t.Fatalf("roundtrip 不一致: %+v", got)
	}
	if s2 := (&cfgStore{p: ""}); s2.set(Config{}) == nil {
		t.Fatal("空路径应报错")
	}
}
