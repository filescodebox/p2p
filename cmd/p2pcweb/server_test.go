package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGuardTokenAndHost(t *testing.T) {
	s := &Server{token: "secret", loopback: true, port: "12348"}
	h := s.guard(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	get := func(host, target string, header string) int {
		r := httptest.NewRequest("GET", target, nil)
		r.Host = host
		if header != "" {
			r.Header.Set("X-P2PCWEB", header)
		}
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}

	if c := get("127.0.0.1:12348", "/?t=secret", ""); c != 200 {
		t.Fatalf("首屏文档查询令牌被拒: %d", c)
	}
	if c := get("127.0.0.1:12348", "/", "secret"); c != 200 {
		t.Fatalf("头令牌被拒: %d", c)
	}
	if c := get("localhost:12348", "/?t=secret", ""); c != 200 {
		t.Fatalf("localhost 被拒: %d", c)
	}
	// API 一律头令牌:query 令牌只放行首屏文档,防凭据进每个请求的 URL(日志面)
	if c := get("127.0.0.1:12348", "/api/state?t=secret", ""); c != http.StatusForbidden {
		t.Fatalf("API query 令牌应被拒, got %d", c)
	}
	for name, c := range map[string]int{
		"缺令牌":     get("127.0.0.1:12348", "/", ""),
		"错令牌":     get("127.0.0.1:12348", "/?t=wrong", ""),
		"rebind":  get("evil.example.com:12348", "/?t=secret", ""),
		"端口不符":    get("127.0.0.1:9999", "/?t=secret", ""),
		"无端口Host": get("127.0.0.1", "/?t=secret", ""),
	} {
		if c != http.StatusForbidden {
			t.Fatalf("%s 期望 403, got %d", name, c)
		}
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	cases := [][2]string{
		{"10.0.0.1", "http://10.0.0.1"},
		{"http://a.b/", "http://a.b"},
		{`"https://c.d/"`, "https://c.d"},
		{"  1.2.3.4:8080  ", "http://1.2.3.4:8080"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeBaseURL(c[0]); got != c[1] {
			t.Errorf("normalizeBaseURL(%q) = %q, want %q", c[0], got, c[1])
		}
	}
}

func TestHandleRecvValidation(t *testing.T) {
	s := &Server{token: "t", mgr: NewManager(), cfg: &cfgStore{}}

	r := httptest.NewRequest("POST", "/api/recv", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	s.handleRecv(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("空口令期望 400, got %d", w.Code)
	}

	r = httptest.NewRequest("POST", "/api/recv", strings.NewReader(`{"code":"AAAA-BBBB-CCCC"}`))
	w = httptest.NewRecorder()
	s.handleRecv(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("缺 registry 期望 400, got %d", w.Code)
	}
}

func TestHandleSendValidation(t *testing.T) {
	s := &Server{token: "t", maxUpload: 1 << 20, mgr: NewManager()}

	r := httptest.NewRequest("POST", "/api/send", nil)
	w := httptest.NewRecorder()
	s.handleSend(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("缺 registry 期望 400, got %d", w.Code)
	}

	r = httptest.NewRequest("POST", "/api/send?t=1&registry=http://r", strings.NewReader("x"))
	w = httptest.NewRecorder()
	s.handleSend(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("非 multipart 期望 400, got %d", w.Code)
	}
}
