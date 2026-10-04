package client

import (
	"errors"
	"fmt"
	"time"

	"github.com/gorilla/websocket"

	"github.com/filescodebox/p2p/internal/registry"
	"github.com/filescodebox/p2p/internal/signaling"
)

// channel 信令信道客户端侧：接入→hello→等待配对→之后以 data 帧收发。
type channel struct {
	conn   *websocket.Conn
	peerID string
}

var errPeerLeft = errors.New("信令对端已离开")

// joinChannel 接入口令信道。deadline 内未配对报错。
func joinChannel(registryBase, code string, id *nodeIdentity, timeout time.Duration) (*channel, error) {
	hash := registry.CodeHash(code)
	wsURL := toWSURL(registryBase) + "/v1/channel/" + hash
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("信道接入: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	ts := time.Now().Unix()
	if err := conn.WriteJSON(map[string]any{
		"type": "hello", "node_id": id.id, "ts": ts,
		"sig": id.sign(signaling.BuildJoinPayload(id.id, hash, ts)),
	}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("信道 hello: %w", err)
	}

	ch := &channel{conn: conn}
	for ch.peerID == "" {
		var f struct {
			Type    string `json:"type"`
			PeerID  string `json:"peer_id"`
			Message string `json:"message"`
		}
		if err := conn.ReadJSON(&f); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("信道配对等待: %w", err)
		}
		switch f.Type {
		case "waiting":
			// 继续等对方
		case "paired":
			ch.peerID = f.PeerID
		case "error":
			_ = conn.Close()
			return nil, fmt.Errorf("信道拒绝: %s", f.Message)
		default:
			_ = conn.Close()
			return nil, fmt.Errorf("信道帧非法: %s", f.Type)
		}
	}
	// 清除配对期 deadline；后续每帧前重设
	_ = conn.SetReadDeadline(time.Time{})
	return ch, nil
}

// send 发一条 data 帧（PAKE 轮次/加密候选等不透明字节）。
func (c *channel) send(payload []byte) error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return c.conn.WriteJSON(map[string]any{"type": "data", "payload": payload})
}

// recv 收一条 data 帧；对端离开/服务端报错/超时即失败。
func (c *channel) recv() ([]byte, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var f struct {
		Type    string `json:"type"`
		Payload []byte `json:"payload"`
		Message string `json:"message"`
	}
	if err := c.conn.ReadJSON(&f); err != nil {
		return nil, fmt.Errorf("信道接收: %w", err)
	}
	switch f.Type {
	case "data":
		return f.Payload, nil
	case "peer_left":
		return nil, errPeerLeft
	case "error":
		return nil, fmt.Errorf("信道错误: %s", f.Message)
	default:
		return nil, fmt.Errorf("信道帧非法: %s", f.Type)
	}
}

func (c *channel) close() { _ = c.conn.Close() }

// exchange 适配 runPake 的收发契约：send 非 nil 即发送,否则接收。
func (c *channel) exchange() func(send []byte) ([]byte, error) {
	return func(send []byte) ([]byte, error) {
		if send != nil {
			return nil, c.send(send)
		}
		return c.recv()
	}
}

// toWSURL http(s) 基址 → ws(s) 基址。
func toWSURL(base string) string {
	b := trimRight(base)
	switch {
	case hasPrefixFold(b, "https://"):
		return "wss://" + b[len("https://"):]
	case hasPrefixFold(b, "http://"):
		return "ws://" + b[len("http://"):]
	default:
		return "ws://" + b
	}
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && equalFold(s[:len(prefix)], prefix)
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
