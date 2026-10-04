// smokegen 是冒烟辅助 CLI:以真实客户端身份对运行中的 p2pd 跑一遍
// 节点生命周期(注册→公告→解析→撤销→注销),全部断言通过才退出 0。
// 仅用于 scripts/smoke.sh,不属于服务本体。
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/filescodebox/p2p/internal/registry"
)

func main() {
	base := flag.String("base", "http://127.0.0.1:12399", "p2pd 基址")
	code := flag.String("code", "smoke-code-0123456789", "冒烟口令(≥40bit 熵)")
	flag.Parse()
	if err := run(*base, *code); err != nil {
		fmt.Fprintln(os.Stderr, "✗ smoke flow:", err)
		os.Exit(1)
	}
	fmt.Println("✓ 生命周期 flow OK")
}

func run(base, code string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	nodeID := hex.EncodeToString(pub)
	sign := func(payload []byte) string {
		return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	}
	now := func() int64 { return time.Now().Unix() }

	// 1. 注册(租约 1h)
	nodeURL := "http://127.0.0.1:1" // 冒烟环境无真实业务地址,仅验协议面
	ts := now()
	regBody := map[string]any{
		"node_id": nodeID, "url": nodeURL, "name": "smoke-node", "version": "dev",
		"caps": []string{"download"}, "ttl_seconds": 3600,
		"nonce": "smoke-nonce", "ts": ts,
		"sig": sign(registry.BuildPayload(nodeID, nodeURL, "smoke-node", "dev", "download", "3600", "smoke-nonce", fmt.Sprint(ts))),
	}
	if err := post(base, "/v1/nodes/register", regBody, http.StatusOK); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	fmt.Println("  ✓ 注册")

	// 2. 公告
	hash := registry.CodeHash(code)
	expires := now() + 600
	ts = now()
	annBody := map[string]any{
		"node_id": nodeID, "code_hash": hash, "expires_at": expires,
		"size_hint": 0, "ts": ts,
		"sig": sign(registry.BuildPayload(nodeID, hash, fmt.Sprint(expires), "0", fmt.Sprint(ts))),
	}
	if err := post(base, "/v1/announces", annBody, http.StatusOK); err != nil {
		return fmt.Errorf("announce: %w", err)
	}
	fmt.Println("  ✓ 公告")

	// 3. 解析命中
	var resolved struct {
		NodeID string `json:"node_id"`
		URL    string `json:"url"`
	}
	if err := getJSON(base, "/v1/resolve/"+hash, http.StatusOK, &resolved); err != nil {
		return fmt.Errorf("resolve hit: %w", err)
	}
	if resolved.NodeID != nodeID || resolved.URL != nodeURL {
		return fmt.Errorf("resolve 返回不匹配: %+v", resolved)
	}
	fmt.Println("  ✓ 解析命中")

	// 4. 撤销
	ts = now()
	if err := doJSON(http.MethodDelete, base, "/v1/announces/"+hash,
		map[string]any{"node_id": nodeID, "ts": ts, "sig": sign(registry.BuildPayload(nodeID, hash, fmt.Sprint(ts)))},
		http.StatusOK, nil); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	fmt.Println("  ✓ 撤销")

	// 5. 解析落空
	if err := getJSON(base, "/v1/resolve/"+hash, http.StatusNotFound, nil); err != nil {
		return fmt.Errorf("resolve miss after revoke: %w", err)
	}
	fmt.Println("  ✓ 撤销后解析 404")

	// 6. 注销节点
	ts = now()
	if err := doJSON(http.MethodDelete, base, "/v1/nodes/"+nodeID,
		map[string]any{"node_id": nodeID, "ts": ts, "sig": sign(registry.BuildPayload(nodeID, fmt.Sprint(ts)))},
		http.StatusOK, nil); err != nil {
		return fmt.Errorf("deregister: %w", err)
	}
	return nil
}

func post(base, path string, body any, wantStatus int) error {
	return doJSON(http.MethodPost, base, path, body, wantStatus, nil)
}

func doJSON(method, base, path string, body any, wantStatus int, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != wantStatus {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: 期望 %d 实际 %d: %s", method, path, wantStatus, resp.StatusCode, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func getJSON(base, path string, wantStatus int, out any) error {
	return doJSON(http.MethodGet, base, path, nil, wantStatus, out)
}
