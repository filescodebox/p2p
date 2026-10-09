// Package memory 是 store.Store 的进程内存实现:RWMutex + map + 惰性过期。
// 过期判定在读路径完成(store.Expired),Sweep 负责物理回收。
package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/pigeonbox/p2p/internal/store"
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

// Stats 当前(未过滤过期)条目数,启动日志用。
func (s *Store) Stats() (nodes, announces int, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nodes), len(s.announces), nil
}

// snapshotData 快照文件形态(JSON)。带版本号,未来字段演进可迁移。
type snapshotData struct {
	Version   int              `json:"version"`
	Nodes     []store.Node     `json:"nodes"`
	Announces []store.Announce `json:"announces"`
}

const snapshotVersion = 1

// Snapshot 序列化全部内容(含未过期项;过期项恢复后由清扫周期回收)。
// 与 Restore 成对,供 p2pd 的可选持久化(重启不再有公告失联窗口)。
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.RLock()
	nodes := make([]store.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		nodes = append(nodes, n)
	}
	announces := make([]store.Announce, 0, len(s.announces))
	for _, a := range s.announces {
		announces = append(announces, a)
	}
	s.mu.RUnlock()
	return json.Marshal(snapshotData{Version: snapshotVersion, Nodes: nodes, Announces: announces})
}

// Restore 用快照整体替换存储内容。损坏/版本不识别返回错误,调用方决定
// 回退空存储。过期项照常读入——读路径的 Expired 判定与清扫兜底。
func (s *Store) Restore(data []byte) error {
	var sd snapshotData
	if err := json.Unmarshal(data, &sd); err != nil {
		return fmt.Errorf("快照解析: %w", err)
	}
	if sd.Version != snapshotVersion {
		return fmt.Errorf("快照版本不识别: %d", sd.Version)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes = make(map[string]store.Node, len(sd.Nodes))
	for _, n := range sd.Nodes {
		if n.ID == "" {
			continue
		}
		s.nodes[n.ID] = n
	}
	s.announces = make(map[string]store.Announce, len(sd.Announces))
	for _, a := range sd.Announces {
		if a.CodeHash == "" {
			continue
		}
		s.announces[a.CodeHash] = a
	}
	return nil
}
