package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/filescodebox/p2p/internal/store"
	"github.com/filescodebox/p2p/internal/store/memory"
)

// ---- 压测基准(M4): 注册/公告/解析热路径(含 Ed25519 验签与内存读写) ----

type benchEnv struct {
	svc  *Service
	node string
	priv ed25519.PrivateKey
}

func newBenchEnv(b *testing.B) *benchEnv {
	b.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	svc := New(Params{
		Store: memory.New(), MinNodeTTL: time.Minute, MaxNodeTTL: 24 * time.Hour,
		MaxAnnounces: 1 << 20, MaxAnnounceTTL: 24 * time.Hour,
	})
	id := hex.EncodeToString(pub)
	ts := time.Now().Unix()
	in := RegisterInput{
		NodeID: id, URL: "https://bench", Name: "b", Version: "1",
		Caps: []string{"download"}, TTLSeconds: 3600, Nonce: "n", TS: ts,
	}
	in.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv,
		BuildPayload(id, in.URL, in.Name, in.Version, "download", "3600", "n", fmt.Sprint(ts))))
	if _, err := svc.RegisterNode(context.Background(), in, "1.2.3.4"); err != nil {
		b.Fatal(err)
	}
	return &benchEnv{svc: svc, node: id, priv: priv}
}

// signAnnounce 预生成一条合法公告输入(签名在客户端侧,服务端热路径只含验签)。
func (e *benchEnv) signAnnounce(code string, expires time.Time) AnnounceInput {
	hash := CodeHash(code)
	ts := time.Now().Unix()
	return AnnounceInput{
		NodeID: e.node, CodeHash: hash, ExpiresAt: expires.Unix(), SizeHint: 0, TS: ts,
		Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(e.priv,
			BuildPayload(e.node, hash, fmt.Sprint(expires.Unix()), "0", fmt.Sprint(ts)))),
	}
}

// BenchmarkAnnounce 公告热路径: Ed25519 验签 + 配额计数 + 内存写(同一 hash 为更新路径)。
func BenchmarkAnnounce(b *testing.B) {
	e := newBenchEnv(b)
	in := e.signAnnounce("bench-code-1234567890", time.Now().Add(time.Hour))
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.svc.Announce(ctx, in); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkResolveHit 解析热路径: SHA-256 + 内存读 + 双过期判定。
func BenchmarkResolveHit(b *testing.B) {
	e := newBenchEnv(b)
	ctx := context.Background()
	in := e.signAnnounce("bench-code-1234567890", time.Now().Add(time.Hour))
	if _, err := e.svc.Announce(ctx, in); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := e.svc.Resolve(ctx, CodeHash("bench-code-1234567890")); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkResolveMiss 解析未命中(限流器在 HTTP 层,此处为纯服务路径)。
func BenchmarkResolveMiss(b *testing.B) {
	e := newBenchEnv(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// miss 路径返回 ErrNotFound 属预期,基准测的是查询+判定开销
		if _, _, err := e.svc.Resolve(ctx, fmt.Sprintf("%064x", i)); err != nil && !errors.Is(err, ErrNotFound) {
			b.Fatal(err)
		}
	}
}

// BenchmarkStoreAnnounceChurn 纯存储层: 不同 hash 连续写入(最坏插入路径)。
func BenchmarkStoreAnnounceChurn(b *testing.B) {
	st := memory.New()
	ctx := context.Background()
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := st.PutAnnounce(ctx, memAnnounce(fmt.Sprintf("h%d", i), now)); err != nil {
			b.Fatal(err)
		}
	}
}

func memAnnounce(hash string, expires time.Time) store.Announce {
	return store.Announce{CodeHash: hash, NodeID: "n", ExpiresAt: expires}
}
