package signaling

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/filescodebox/p2p/internal/registry"
	"github.com/filescodebox/p2p/internal/store/memory"
)

// ---- 脚手架 ----

type keyPair struct {
	id   string
	priv ed25519.PrivateKey
}

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{id: hex.EncodeToString(pub), priv: priv}
}

func (k keyPair) sign(t *testing.T, payload []byte) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv, payload))
}

func newFixture(t *testing.T, mutate func(*Config)) (*httptest.Server, *registry.Service) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.PingPeriod = 50 * time.Millisecond
	if mutate != nil {
		mutate(&cfg)
	}
	st := memory.New()
	svc := registry.New(registry.Params{
		Store: st, MinNodeTTL: time.Minute, MaxNodeTTL: time.Hour,
		MaxAnnounces: 10, MaxAnnounceTTL: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	hub := NewHub(ctx, cfg, svc, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/channel/{hash}", hub.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, svc
}

func registerNode(t *testing.T, svc *registry.Service, baseURL string) keyPair {
	t.Helper()
	k := newKeyPair(t)
	ts := time.Now().Unix()
	in := registry.RegisterInput{
		NodeID: k.id, URL: baseURL, Name: "n", Version: "1",
		Caps: []string{"download"}, TTLSeconds: 600, Nonce: "nc", TS: ts,
	}
	in.Sig = k.sign(t, registry.BuildPayload(in.NodeID, in.URL, in.Name, in.Version,
		"download", "600", "nc", fmt.Sprint(ts)))
	if _, err := svc.RegisterNode(context.Background(), in, "10.0.0.1"); err != nil {
		t.Fatalf("注册节点: %v", err)
	}
	return k
}

func dial(t *testing.T, wsBase, hash string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(wsBase+"/v1/channel/"+hash, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func hello(t *testing.T, conn *websocket.Conn, k keyPair, hash string, ts int64) {
	t.Helper()
	if err := conn.WriteJSON(map[string]any{
		"type": "hello", "node_id": k.id, "ts": ts, "sig": k.sign(t, BuildJoinPayload(k.id, hash, ts)),
	}); err != nil {
		t.Fatalf("hello: %v", err)
	}
}

type frame struct {
	Type    string `json:"type"`
	PeerID  string `json:"peer_id"`
	From    string `json:"from"`
	Payload []byte `json:"payload"`
	Message string `json:"message"`
}

// readNext 读下一帧；服务端关闭则返回关闭码(>0)。
func readNext(t *testing.T, conn *websocket.Conn) (frame, int) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		if ce, ok := err.(*websocket.CloseError); ok {
			return frame{}, ce.Code
		}
		t.Fatalf("read: %v", err)
	}
	var f frame
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	return f, 0
}

func mustFrame(t *testing.T, conn *websocket.Conn) frame {
	t.Helper()
	f, code := readNext(t, conn)
	if code != 0 {
		t.Fatalf("期望数据帧,得到关闭码 %d", code)
	}
	return f
}

// expectClose 循环读直到服务端关闭,校验关闭码(途中收集帧供调用方断言)。
func expectClose(t *testing.T, conn *websocket.Conn, wantCode int) []frame {
	t.Helper()
	var seen []frame
	for {
		f, code := readNext(t, conn)
		if code != 0 {
			if wantCode != 0 && code != wantCode {
				t.Fatalf("关闭码: 期望 %d 实际 %d", wantCode, code)
			}
			return seen
		}
		seen = append(seen, f)
	}
}

func sendData(t *testing.T, conn *websocket.Conn, payload []byte) {
	t.Helper()
	if err := conn.WriteJSON(map[string]any{"type": "data", "payload": payload}); err != nil {
		t.Fatalf("send data: %v", err)
	}
}

// ---- 用例 ----

func TestPairingAndRelay(t *testing.T) {
	srv, svc := newFixture(t, nil)
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	a := registerNode(t, svc, "https://a")
	b := registerNode(t, svc, "https://b")
	c := registerNode(t, svc, "https://c")
	hash := registry.CodeHash("pair-code-1234567890")
	ts := time.Now().Unix()

	connA := dial(t, ws, hash)
	hello(t, connA, a, hash, ts)
	if f := mustFrame(t, connA); f.Type != "waiting" {
		t.Fatalf("首个接入应 waiting,得到 %s", f.Type)
	}

	// 第三人此时加入(只有 A 在等)——应与 A 配对而不是拒绝? 不:C 与 A 配对会破坏
	// "同一口令双方"语义吗? 服务端不知道谁是谁——配对是位置性的,身份核对是
	// 客户端契约(paired.peer_id vs resolve)。本用例只验证机制,故 C 未被使用。
	connB := dial(t, ws, hash)
	hello(t, connB, b, hash, ts)

	if f := mustFrame(t, connA); f.Type != "paired" || f.PeerID != b.id {
		t.Fatalf("A 应收到 paired(peer_id=%s),得到 %+v", b.id, f)
	}
	if f := mustFrame(t, connB); f.Type != "paired" || f.PeerID != a.id {
		t.Fatalf("B 应收到 paired(peer_id=%s),得到 %+v", a.id, f)
	}

	// 双向转发,from 字段=发送方身份
	sendData(t, connA, []byte("ping"))
	if f := mustFrame(t, connB); f.Type != "data" || f.From != a.id || string(f.Payload) != "ping" {
		t.Fatalf("B 应收到 A 的 ping,得到 %+v", f)
	}
	sendData(t, connB, []byte("pong"))
	if f := mustFrame(t, connA); f.Type != "data" || f.From != b.id || string(f.Payload) != "pong" {
		t.Fatalf("A 应收到 B 的 pong,得到 %+v", f)
	}

	// 第三人拒入(信道已满) → 4002
	connC := dial(t, ws, hash)
	hello(t, connC, c, hash, ts)
	expectClose(t, connC, closeBusy)

	// A 断开 → B 收 peer_left 再被关闭
	_ = connA.Close()
	frames := expectClose(t, connB, websocket.CloseNormalClosure)
	if len(frames) == 0 || frames[len(frames)-1].Type != "peer_left" {
		t.Fatalf("B 应收到 peer_left,得到 %v", frames)
	}
}

func TestHelloAuthFailures(t *testing.T) {
	srv, svc := newFixture(t, nil)
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	a := registerNode(t, svc, "https://a")
	stranger := newKeyPair(t) // 未注册
	b := registerNode(t, svc, "https://b")
	hash := registry.CodeHash("auth-code-1234567890")

	t.Run("坏签名", func(t *testing.T) {
		conn := dial(t, ws, hash)
		ts := time.Now().Unix()
		// 用 B 的私钥给 A 的身份签名 → 校验失败
		if err := conn.WriteJSON(map[string]any{
			"type": "hello", "node_id": a.id, "ts": ts,
			"sig": b.sign(t, BuildJoinPayload(a.id, hash, ts)),
		}); err != nil {
			t.Fatal(err)
		}
		expectClose(t, conn, closeDenied)
	})
	t.Run("未注册节点", func(t *testing.T) {
		conn := dial(t, ws, hash)
		hello(t, conn, stranger, hash, time.Now().Unix())
		expectClose(t, conn, closeDenied)
	})
	t.Run("时间戳过期", func(t *testing.T) {
		conn := dial(t, ws, hash)
		hello(t, conn, a, hash, time.Now().Add(-10*time.Minute).Unix())
		expectClose(t, conn, closeDenied)
	})
	t.Run("hello 缺失", func(t *testing.T) {
		conn := dial(t, ws, hash)
		_ = conn.WriteJSON(map[string]any{"type": "data", "payload": []byte("x")})
		expectClose(t, conn, closeBadHello)
	})
}

func TestHelloTimeout(t *testing.T) {
	srv, _ := newFixture(t, func(c *Config) { c.HelloTimeout = 150 * time.Millisecond })
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	hash := registry.CodeHash("hello-timeout-code-1")
	conn := dial(t, ws, hash)
	expectClose(t, conn, closeBadHello)
}

func TestIdleWithoutPong(t *testing.T) {
	srv, svc := newFixture(t, func(c *Config) {
		c.IdleTimeout = 300 * time.Millisecond
		c.PingPeriod = 80 * time.Millisecond
	})
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	a := registerNode(t, svc, "https://a")
	b := registerNode(t, svc, "https://b")
	hash := registry.CodeHash("idle-code-1234567890")
	ts := time.Now().Unix()

	connA := dial(t, ws, hash)
	hello(t, connA, a, hash, ts)
	connB := dial(t, ws, hash)
	hello(t, connB, b, hash, ts)
	mustFrame(t, connA) // paired
	mustFrame(t, connB)

	// 吞掉服务端 ping(不回 pong)也不发数据 → 空闲断开
	for _, conn := range []*websocket.Conn{connA, connB} {
		conn.SetPingHandler(func(string) error { return nil })
	}
	for _, conn := range []*websocket.Conn{connA, connB} {
		expectClose(t, conn, websocket.CloseNormalClosure)
	}
}

func TestPongKeepsAlive(t *testing.T) {
	srv, svc := newFixture(t, func(c *Config) {
		c.IdleTimeout = 400 * time.Millisecond
		c.PingPeriod = 80 * time.Millisecond
	})
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	a := registerNode(t, svc, "https://a")
	b := registerNode(t, svc, "https://b")
	hash := registry.CodeHash("pong-code-1234567890")
	ts := time.Now().Unix()

	connA := dial(t, ws, hash)
	hello(t, connA, a, hash, ts)
	connB := dial(t, ws, hash)
	hello(t, connB, b, hash, ts)

	// gorilla 客户端在 ReadMessage 循环中自动回 pong——真实客户端亦然。
	// 起读泵排帧(收到进 channel),否则 ping 积压无人应答,服务端按空闲断开。
	type pump struct{ frames chan frame }
	startPump := func(conn *websocket.Conn) *pump {
		p := &pump{frames: make(chan frame, 64)}
		go func() {
			for {
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, raw, err := conn.ReadMessage()
				if err != nil {
					return
				}
				var f frame
				if json.Unmarshal(raw, &f) == nil {
					p.frames <- f
				}
			}
		}()
		return p
	}
	pA, pB := startPump(connA), startPump(connB)
	<-pA.frames // waiting
	<-pA.frames // paired
	<-pB.frames // paired

	// 空闲期远超 IdleTimeout,期间零数据帧,仅 pong 续期 → 连接必须存活
	time.Sleep(1 * time.Second)
	sendData(t, connA, []byte("still-alive"))
	select {
	case f := <-pB.frames:
		if f.Type != "data" || string(f.Payload) != "still-alive" {
			t.Fatalf("pong 保活失败: %+v", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("3s 内未收到转发帧(连接已被服务端断开?)")
	}
}

func TestSessionTTL(t *testing.T) {
	srv, svc := newFixture(t, func(c *Config) { c.SessionTTL = 400 * time.Millisecond })
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	a := registerNode(t, svc, "https://a")
	hash := registry.CodeHash("ttl-code-1234567890")
	connA := dial(t, ws, hash)
	hello(t, connA, a, hash, time.Now().Unix())
	mustFrame(t, connA) // waiting

	// janitor 间隔 = ttl/2 = 200ms;等 1.2s 必然被清扫
	_ = connA.SetReadDeadline(time.Now().Add(3 * time.Second))
	expectClose(t, connA, 0)
}

func TestPerNodeSessionCap(t *testing.T) {
	srv, svc := newFixture(t, func(c *Config) { c.MaxSessionsPerNode = 1 })
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	a := registerNode(t, svc, "https://a")
	h1 := registry.CodeHash("cap-code-1-1234567890")
	h2 := registry.CodeHash("cap-code-2-1234567890")

	conn1 := dial(t, ws, h1)
	hello(t, conn1, a, h1, time.Now().Unix())
	mustFrame(t, conn1) // waiting

	conn2 := dial(t, ws, h2)
	hello(t, conn2, a, h2, time.Now().Unix())
	expectClose(t, conn2, closeBusy)
}

func TestOversizeFrameRejected(t *testing.T) {
	srv, svc := newFixture(t, func(c *Config) { c.MaxFrameBytes = 1024 })
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	a := registerNode(t, svc, "https://a")
	b := registerNode(t, svc, "https://b")
	hash := registry.CodeHash("oversize-code-123456")
	ts := time.Now().Unix()

	connA := dial(t, ws, hash)
	hello(t, connA, a, hash, ts)
	mustFrame(t, connA) // waiting
	connB := dial(t, ws, hash)
	hello(t, connB, b, hash, ts)
	mustFrame(t, connA) // paired
	mustFrame(t, connB)

	big := make([]byte, 2000) // > MaxFrameBytes(1024),JSON 包裹后 < 读上限(6KB)
	sendData(t, connA, big)
	frames := expectClose(t, connA, websocket.CloseNormalClosure)
	if len(frames) == 0 || frames[0].Type != "error" {
		t.Fatalf("超限帧应先收 error 帧,得到 %v", frames)
	}
	// B 收 peer_left
	framesB := expectClose(t, connB, websocket.CloseNormalClosure)
	if len(framesB) == 0 || framesB[len(framesB)-1].Type != "peer_left" {
		t.Fatalf("B 应收到 peer_left,得到 %v", framesB)
	}
}

func TestJoinPayloadContract(t *testing.T) {
	got := string(BuildJoinPayload("abc", "cafe", 1700000000))
	if got != "channel-join\nabc\ncafe\n1700000000" {
		t.Fatalf("join 负载契约漂移: %q", got)
	}
}
