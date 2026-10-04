package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/filescodebox/p2p/internal/store/memory"
)

// ---- 测试脚手架 ----

type testNode struct {
	id   string
	priv ed25519.PrivateKey
}

func newNode(t *testing.T) testNode {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testNode{id: hex.EncodeToString(pub), priv: priv}
}

func (n testNode) sign(t *testing.T, parts ...string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(ed25519.Sign(n.priv, BuildPayload(parts...)))
}

type fixture struct {
	svc *Service
	st  *memory.Store
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st := memory.New()
	svc := New(Params{
		Store:          st,
		MinNodeTTL:     time.Minute,
		MaxNodeTTL:     24 * time.Hour,
		MaxAnnounces:   2,
		MaxAnnounceTTL: time.Hour,
	})
	return &fixture{svc: svc, st: st}
}

func (f *fixture) register(t *testing.T, n testNode, ttlSec int64) {
	t.Helper()
	in := RegisterInput{
		NodeID: n.id, URL: "https://node-a.example.com", Name: "node-a", Version: "v1",
		Caps: []string{"download"}, TTLSeconds: ttlSec, Nonce: "n", TS: time.Now().Unix(),
	}
	in.Sig = n.sign(t, in.NodeID, in.URL, in.Name, in.Version, "download",
		itoa(in.TTLSeconds), in.Nonce, itoa(in.TS))
	if _, err := f.svc.RegisterNode(context.Background(), in, "10.0.0.1"); err != nil {
		t.Fatalf("注册失败: %v", err)
	}
}

func (f *fixture) announce(t *testing.T, n testNode, code string, expiresIn time.Duration) {
	t.Helper()
	hash := CodeHash(code)
	expires := time.Now().Add(expiresIn).Unix()
	ts := time.Now().Unix()
	in := AnnounceInput{NodeID: n.id, CodeHash: hash, ExpiresAt: expires, SizeHint: 0, TS: ts}
	in.Sig = n.sign(t, in.NodeID, in.CodeHash, itoa(expires), "0", itoa(ts))
	if _, err := f.svc.Announce(context.Background(), in); err != nil {
		t.Fatalf("公告失败: %v", err)
	}
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

// ---- 用例 ----

func TestRegisterAnnounceResolveFlow(t *testing.T) {
	f := newFixture(t)
	n := newNode(t)
	f.register(t, n, 3600)
	f.announce(t, n, "正确口令-code-1234567890", time.Hour)

	a, node, err := f.svc.Resolve(context.Background(), CodeHash("正确口令-code-1234567890"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if node.ID != n.id || node.URL != "https://node-a.example.com" {
		t.Fatalf("resolve 返回错误节点: %+v", node)
	}
	if a.NodeID != n.id {
		t.Fatalf("公告归属错误: %+v", a)
	}
}

func TestRegisterBadSignature(t *testing.T) {
	f := newFixture(t)
	n := newNode(t)
	other := newNode(t)
	in := RegisterInput{
		NodeID: n.id, URL: "https://x.example.com", TTLSeconds: 600, Nonce: "n", TS: time.Now().Unix(),
	}
	// 用错误私钥签名
	in.Sig = other.sign(t, in.NodeID, in.URL, "", "", "", itoa(in.TTLSeconds), in.Nonce, itoa(in.TS))
	_, err := f.svc.RegisterNode(context.Background(), in, "1.1.1.1")
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("期望 ErrBadSignature,得到: %v", err)
	}
}

func TestRegisterStaleTimestamp(t *testing.T) {
	f := newFixture(t)
	n := newNode(t)
	ts := time.Now().Add(-10 * time.Minute).Unix()
	in := RegisterInput{NodeID: n.id, URL: "https://x.com", TTLSeconds: 600, Nonce: "n", TS: ts}
	in.Sig = n.sign(t, in.NodeID, in.URL, "", "", "", itoa(600), "n", itoa(ts))
	_, err := f.svc.RegisterNode(context.Background(), in, "1.1.1.1")
	if !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("期望 ErrStaleTimestamp,得到: %v", err)
	}
}

func TestRegisterTTLBounds(t *testing.T) {
	f := newFixture(t)
	n := newNode(t)
	for _, ttl := range []int64{10, 25 * 3600} { // 低于 min / 高于 max
		in := RegisterInput{NodeID: n.id, URL: "https://x.com", TTLSeconds: ttl, Nonce: "n", TS: time.Now().Unix()}
		in.Sig = n.sign(t, in.NodeID, in.URL, "", "", "", itoa(ttl), "n", itoa(in.TS))
		if _, err := f.svc.RegisterNode(context.Background(), in, "1.1.1.1"); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ttl=%d 期望 ErrInvalidRequest,得到: %v", ttl, err)
		}
	}
}

func TestRegisterTokenMode(t *testing.T) {
	st := memory.New()
	svc := New(Params{Store: st, RequireToken: "secret", MinNodeTTL: time.Minute, MaxNodeTTL: time.Hour, MaxAnnounces: 1, MaxAnnounceTTL: time.Hour})
	n := newNode(t)
	in := RegisterInput{NodeID: n.id, URL: "https://x.com", TTLSeconds: 600, Nonce: "n", TS: time.Now().Unix(), Token: "wrong"}
	in.Sig = n.sign(t, in.NodeID, in.URL, "", "", "", itoa(600), "n", itoa(in.TS))
	if _, err := svc.RegisterNode(context.Background(), in, "1.1.1.1"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("期望 ErrUnauthorized,得到: %v", err)
	}
	in.Token = "secret"
	in.TS = time.Now().Unix()
	in.Sig = n.sign(t, in.NodeID, in.URL, "", "", "", itoa(600), "n", itoa(in.TS))
	if _, err := svc.RegisterNode(context.Background(), in, "1.1.1.1"); err != nil {
		t.Fatalf("正确 token 应通过: %v", err)
	}
}

func TestAnnounceRequiresLiveNode(t *testing.T) {
	f := newFixture(t)
	n := newNode(t)
	// 未注册节点直接公告
	hash := CodeHash("x-1234567890")
	expires := time.Now().Add(time.Hour).Unix()
	ts := time.Now().Unix()
	in := AnnounceInput{NodeID: n.id, CodeHash: hash, ExpiresAt: expires, TS: ts}
	in.Sig = n.sign(t, in.NodeID, in.CodeHash, itoa(expires), "0", itoa(ts))
	if _, err := f.svc.Announce(context.Background(), in); !errors.Is(err, ErrNotFound) {
		t.Fatalf("期望 ErrNotFound,得到: %v", err)
	}
}

func TestAnnounceConflictFirstWins(t *testing.T) {
	f := newFixture(t)
	a, b := newNode(t), newNode(t)
	f.register(t, a, 3600)
	f.register(t, b, 3600)
	code := "conflict-code-1234567890"
	f.announce(t, a, code, time.Hour)

	hash := CodeHash(code)
	expires := time.Now().Add(time.Hour).Unix()
	ts := time.Now().Unix()
	in := AnnounceInput{NodeID: b.id, CodeHash: hash, ExpiresAt: expires, TS: ts}
	in.Sig = b.sign(t, in.NodeID, in.CodeHash, itoa(expires), "0", itoa(ts))
	if _, err := f.svc.Announce(context.Background(), in); !errors.Is(err, ErrConflict) {
		t.Fatalf("期望 ErrConflict(先到先得),得到: %v", err)
	}
}

func TestAnnounceQuota(t *testing.T) {
	f := newFixture(t) // MaxAnnounces=2
	n := newNode(t)
	f.register(t, n, 3600)
	f.announce(t, n, "quota-code-000000001", time.Hour)
	f.announce(t, n, "quota-code-000000002", time.Hour)

	hash := CodeHash("quota-code-000000003")
	expires := time.Now().Add(time.Hour).Unix()
	ts := time.Now().Unix()
	in := AnnounceInput{NodeID: n.id, CodeHash: hash, ExpiresAt: expires, TS: ts}
	in.Sig = n.sign(t, in.NodeID, in.CodeHash, itoa(expires), "0", itoa(ts))
	if _, err := f.svc.Announce(context.Background(), in); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("期望 ErrQuotaExceeded,得到: %v", err)
	}
}

func TestAnnounceExpiryBound(t *testing.T) {
	f := newFixture(t) // MaxAnnounceTTL=1h
	n := newNode(t)
	f.register(t, n, 3600)

	hash := CodeHash("toolong-code-1234567890")
	expires := time.Now().Add(2 * time.Hour).Unix()
	ts := time.Now().Unix()
	in := AnnounceInput{NodeID: n.id, CodeHash: hash, ExpiresAt: expires, TS: ts}
	in.Sig = n.sign(t, in.NodeID, in.CodeHash, itoa(expires), "0", itoa(ts))
	if _, err := f.svc.Announce(context.Background(), in); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("超 MaxAnnounceTTL 期望 ErrInvalidRequest,得到: %v", err)
	}
}

func TestResolveExpiry(t *testing.T) {
	f := newFixture(t)
	n := newNode(t)
	f.register(t, n, 3600)
	f.announce(t, n, "expire-code-1234567890", time.Hour)

	code := "expire-code-1234567890"
	// 时钟推进 2h:公告与节点租约双过期
	f.svc.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, _, err := f.svc.Resolve(context.Background(), CodeHash(code)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("过期公告期望 ErrNotFound,得到: %v", err)
	}
}

func TestResolveNodeGone(t *testing.T) {
	f := newFixture(t)
	n := newNode(t)
	f.register(t, n, 3600)
	f.announce(t, n, "gone-code-1234567890", time.Hour)

	// 节点被管理端强制下线,但公告仍在 → 解析应视为不存在
	if err := f.svc.AdminDeleteNode(context.Background(), n.id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Resolve(context.Background(), CodeHash("gone-code-1234567890")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("节点失效后期望 ErrNotFound,得到: %v", err)
	}
}

func TestRevokeOnlyOwner(t *testing.T) {
	f := newFixture(t)
	owner, other := newNode(t), newNode(t)
	f.register(t, owner, 3600)
	f.register(t, other, 3600)
	code := "owner-code-1234567890"
	f.announce(t, owner, code, time.Hour)

	hash := CodeHash(code)
	ts := time.Now().Unix()
	in := RevokeInput{NodeID: other.id, CodeHash: hash, TS: ts}
	in.Sig = other.sign(t, in.NodeID, in.CodeHash, itoa(ts))
	if err := f.svc.RevokeAnnounce(context.Background(), in); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("非宣告节点撤销期望 ErrUnauthorized,得到: %v", err)
	}

	in2 := RevokeInput{NodeID: owner.id, CodeHash: hash, TS: ts}
	in2.Sig = owner.sign(t, in2.NodeID, in2.CodeHash, itoa(ts))
	if err := f.svc.RevokeAnnounce(context.Background(), in2); err != nil {
		t.Fatalf("宣告节点撤销应成功: %v", err)
	}
	if _, _, err := f.svc.Resolve(context.Background(), hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("撤销后应解析不到: %v", err)
	}
}

func TestDeregisterCascade(t *testing.T) {
	f := newFixture(t)
	n := newNode(t)
	f.register(t, n, 3600)
	f.announce(t, n, "cascade-code-1234567890", time.Hour)

	ts := time.Now().Unix()
	in := RevokeInput{NodeID: n.id, TS: ts}
	in.Sig = n.sign(t, in.NodeID, itoa(ts))
	if err := f.svc.DeregisterNode(context.Background(), in); err != nil {
		t.Fatalf("注销失败: %v", err)
	}
	if _, ok, _ := f.st.GetNode(context.Background(), n.id); ok {
		t.Fatal("节点应已删除")
	}
	if c, _ := f.st.CountAnnouncesByNode(context.Background(), n.id); c != 0 {
		t.Fatalf("公告应级联清空,剩 %d", c)
	}
}

func TestSweep(t *testing.T) {
	f := newFixture(t)
	n := newNode(t)
	f.register(t, n, 3600)
	f.announce(t, n, "sweep-code-1234567890", time.Hour)

	f.svc.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	nodes, announces := f.svc.Sweep(context.Background())
	if nodes != 1 || announces != 0 { // 节点过期级联清公告,公告本体清扫计 0
		t.Fatalf("Sweep 回收: nodes=%d announces=%d", nodes, announces)
	}
	if _, ok, _ := f.st.GetNode(context.Background(), n.id); ok {
		t.Fatal("过期节点应被清扫")
	}
	if _, ok, _ := f.st.GetAnnounce(context.Background(), CodeHash("sweep-code-1234567890")); ok {
		t.Fatal("过期节点的公告应被级联清扫")
	}
}
