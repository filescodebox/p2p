package memory

import (
	"context"
	"testing"
	"time"

	"github.com/filescodebox/p2p/internal/store"
)

func TestNodeCRUD(t *testing.T) {
	s := New()
	ctx := context.Background()
	now := time.Now()

	n := store.Node{ID: "aa", URL: "http://x", ExpiresAt: now.Add(time.Hour)}
	if err := s.UpsertNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetNode(ctx, "aa")
	if err != nil || !ok || got.URL != "http://x" {
		t.Fatalf("GetNode: ok=%v err=%v got=%+v", ok, err, got)
	}
	if err := s.UpsertNode(ctx, store.Node{ID: "aa", URL: "http://y", ExpiresAt: now.Add(2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.GetNode(ctx, "aa")
	if got.URL != "http://y" {
		t.Fatalf("upsert 未覆盖: %+v", got)
	}
	if ok, _ := s.DeleteNode(ctx, "aa"); !ok {
		t.Fatal("DeleteNode 应命中")
	}
	if _, ok, _ := s.GetNode(ctx, "aa"); ok {
		t.Fatal("删除后不应存在")
	}
}

func TestAnnounceCascadeAndCount(t *testing.T) {
	s := New()
	ctx := context.Background()
	now := time.Now()

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.UpsertNode(ctx, store.Node{ID: "n1", ExpiresAt: now.Add(time.Hour)}))
	must(s.PutAnnounce(ctx, store.Announce{CodeHash: "h1", NodeID: "n1", ExpiresAt: now.Add(time.Hour)}))
	must(s.PutAnnounce(ctx, store.Announce{CodeHash: "h2", NodeID: "n1", ExpiresAt: now.Add(time.Hour)}))
	must(s.PutAnnounce(ctx, store.Announce{CodeHash: "h3", NodeID: "n2", ExpiresAt: now.Add(time.Hour)}))

	if c, _ := s.CountAnnouncesByNode(ctx, "n1"); c != 2 {
		t.Fatalf("CountAnnouncesByNode(n1)=%d, 期望 2", c)
	}
	removed, _ := s.DeleteAnnouncesByNode(ctx, "n1")
	if removed != 2 {
		t.Fatalf("级联删除=%d, 期望 2", removed)
	}
	if _, ok, _ := s.GetAnnounce(ctx, "h1"); ok {
		t.Fatal("h1 应已被级联删除")
	}
	if _, ok, _ := s.GetAnnounce(ctx, "h3"); !ok {
		t.Fatal("h3 属于 n2,不应被删")
	}
}

func TestExpiryReadPath(t *testing.T) {
	s := New()
	ctx := context.Background()
	now := time.Now()

	// store 本身不做过期判定(读路径由 store.Expired 判),这里只验证数据保真
	if err := s.PutAnnounce(ctx, store.Announce{CodeHash: "hx", NodeID: "n", ExpiresAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	a, ok, err := s.GetAnnounce(ctx, "hx")
	if err != nil || !ok {
		t.Fatalf("过期数据仍可读出(判定在上层): ok=%v err=%v", ok, err)
	}
	if !a.Expired(now) {
		t.Fatal("Expired 应为 true")
	}
}
