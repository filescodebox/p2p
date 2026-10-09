package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pigeonbox/p2p/internal/registry"
	"github.com/pigeonbox/p2p/internal/store/memory"
)

// fuzzHandler 最小服务端 handler(开放注册,无管理口令;夹具全 fuzz 复用)。
func fuzzHandler() http.Handler {
	cfg := testConfig("")
	cfg.Registration.MinNodeTTL = time.Minute
	cfg.Registration.MaxNodeTTL = time.Hour
	cfg.Announce.MaxPerNode = 10
	cfg.Announce.MaxTTL = time.Hour
	svc := registry.New(registry.Params{
		Store: memory.New(), MinNodeTTL: cfg.Registration.MinNodeTTL,
		MaxNodeTTL: cfg.Registration.MaxNodeTTL, MaxAnnounces: cfg.Announce.MaxPerNode,
		MaxAnnounceTTL: cfg.Announce.MaxTTL,
	})
	s := New(context.Background(), Params{Service: svc, Config: cfg, Metrics: NewMetrics(), Version: "fuzz"})
	return s.Handler()
}

// fuzzPost 把 body 投给端点,断言不 panic 且不得 5xx
// (memory store 无错误路径,5xx 即解析/校验层失控)。
func fuzzPost(t *testing.T, h http.Handler, path string, body []byte) {
	t.Helper()
	ts := httptest.NewServer(h)
	defer ts.Close()
	resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Skip()
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		t.Fatalf("%s 对任意输入不得 5xx, got %d", path, resp.StatusCode)
	}
}

// FuzzRegisterHandler 任意 JSON 喂注册端点。
func FuzzRegisterHandler(f *testing.F) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	seed, _ := json.Marshal(map[string]any{
		"node_id": hex.EncodeToString(pub), "url": "https://a.b", "name": "n", "version": "v",
		"caps": []string{"direct"}, "ttl_seconds": 600, "nonce": "x", "ts": time.Now().Unix(),
	})
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"ttl_seconds":18446744073709551615}`)) // 整数溢出形态
	f.Add(seed)
	f.Add([]byte(`{"node_id":"` + hex.EncodeToString(pub) + `","url":"http://[::1"}`)) // 畸形 URL

	h := fuzzHandler()
	f.Fuzz(func(t *testing.T, body []byte) {
		fuzzPost(t, h, "/v1/nodes/register", body)
	})
}

// FuzzAnnounceHandler 同上,公告端点(JSON 输入面;路径参数由 resolve 用例覆盖形态)。
func FuzzAnnounceHandler(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"code_hash":"ZZ","expires_at":-1}`))

	h := fuzzHandler()
	f.Fuzz(func(t *testing.T, body []byte) {
		fuzzPost(t, h, "/v1/announces", body)
	})
}
