package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// loadOrCreateNodeKey 加载/生成节点身份密钥（Ed25519 seed hex,0600）。
// 与 p2pd/core 的节点密钥约定一致:密钥丢失=联邦身份更换。
func loadOrCreateNodeKey(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err == nil && len(seed) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(seed), nil
		}
		// 损坏按不存在处理,重新生成
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("读取节点密钥: %w", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成节点密钥: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("创建密钥目录: %w", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		return nil, fmt.Errorf("持久化节点密钥: %w", err)
	}
	return priv, nil
}
