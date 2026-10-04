// Package memory 是 store.Store 的进程内存实现:RWMutex + map + 惰性过期。
// 过期判定在读路径完成(store.Expired),Sweep 负责物理回收。
package memory

import (
	"context"
	"sync"

	"github.com/filescodebox/p2p/internal/store"
)

// Store 内存存储。
type Store struct {
	mu        sync.RWMutex
	nodes     map[string]store.Node
	announces map[string]store.Announce
}

// New 构造内存存储。
func New() *Store {
	return &Store{
		nodes:     make(map[string]store.Node),
		announces: make(map[string]store.Announce),
	}
}

// UpsertNode 写入或刷新节点租约。
func (s *Store) UpsertNode(_ context.Context, n store.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[n.ID] = n
	return nil
}

// GetNode 读取节点(不做过期判定,由调用方用 Expired(now) 判)。
func (s *Store) GetNode(_ context.Context, id string) (store.Node, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.nodes[id]
	return n, ok, nil
}

// DeleteNode 删除节点。
func (s *Store) DeleteNode(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.nodes[id]
	delete(s.nodes, id)
	return ok, nil
}

// ListNodes 返回全部节点的拷贝。
func (s *Store) ListNodes(_ context.Context) ([]store.Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]store.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, n)
	}
	return out, nil
}

// PutAnnounce 写入或刷新公告。
func (s *Store) PutAnnounce(_ context.Context, a store.Announce) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.announces[a.CodeHash] = a
	return nil
}

// GetAnnounce 读取公告。
func (s *Store) GetAnnounce(_ context.Context, codeHash string) (store.Announce, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.announces[codeHash]
	return a, ok, nil
}

// DeleteAnnounce 删除单条公告。
func (s *Store) DeleteAnnounce(_ context.Context, codeHash string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.announces[codeHash]
	delete(s.announces, codeHash)
	return ok, nil
}

// DeleteAnnouncesByNode 级联清除节点的全部公告,返回删除条数。
func (s *Store) DeleteAnnouncesByNode(_ context.Context, nodeID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var removed int64
	for h, a := range s.announces {
		if a.NodeID == nodeID {
			delete(s.announces, h)
			removed++
		}
	}
	return removed, nil
}

// CountAnnouncesByNode 统计节点当前公告数(配额判定用)。
func (s *Store) CountAnnouncesByNode(_ context.Context, nodeID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, a := range s.announces {
		if a.NodeID == nodeID {
			n++
		}
	}
	return n, nil
}

// ListAnnounces 返回全部公告的拷贝(清扫/统计用)。
func (s *Store) ListAnnounces(_ context.Context) ([]store.Announce, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]store.Announce, 0, len(s.announces))
	for _, a := range s.announces {
		out = append(out, a)
	}
	return out, nil
}
