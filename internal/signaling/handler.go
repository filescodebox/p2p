package signaling

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/filescodebox/p2p/internal/registry"
)

// ---- 线上契约（与 README "信令信道协议"逐字对齐，改动须双侧同步） ----

// hello（客户端首帧，须在 HelloTimeout 内）:
//
//	{"type":"hello","node_id":"<hex>","ts":<unix秒>,"sig":"<base64 std>"}
//	sig = Ed25519(node 私钥, "channel-join\n<node_id>\n<code_hash>\n<ts>")
//
// data（配对后客户端帧）: {"type":"data","payload":"<base64>"}
// 服务端帧:
//
//	{"type":"waiting"}                                       首个接入者收到
//	{"type":"paired","peer_id":"<对方 node_id>"}              配对成功双方各收一份
//	{"type":"data","from":"<发送方 node_id>","payload":"…"}    转发
//	{"type":"peer_left"}                                      对方断开
//	{"type":"error","message":"…"}                            协议违规/会话超时
//
// 关闭码: 4001 hello 缺失或非法 / 4002 信道占用或超配额 / 4003 未授权(签名/身份/租约)。
const (
	closeBadHello = 4001
	closeBusy     = 4002
	closeDenied   = 4003
)

const joinPayloadPrefix = "channel-join"

// BuildJoinPayload hello 签名负载契约（逐字节；客户端实现必须一致）。
func BuildJoinPayload(nodeID, codeHash string, ts int64) []byte {
	return []byte(strings.Join([]string{joinPayloadPrefix, nodeID, codeHash, strconv.FormatInt(ts, 10)}, "\n"))
}

type helloFrame struct {
	Type   string `json:"type"`
	NodeID string `json:"node_id"`
	TS     int64  `json:"ts"`
	Sig    string `json:"sig"`
}

type clientFrame struct {
	Type    string `json:"type"`
	Payload []byte `json:"payload"` // encoding/json 对 []byte 自动 base64(std)
}

type serverFrame struct {
	Type    string `json:"type"`
	PeerID  string `json:"peer_id,omitempty"`
	From    string `json:"from,omitempty"`
	Payload []byte `json:"payload,omitempty"`
	Message string `json:"message,omitempty"`
}

func marshalFrame(f serverFrame) ([]byte, bool) {
	b, err := json.Marshal(f)
	if err != nil {
		return nil, false
	}
	return b, true
}

// ---- WS 升级与准入 ----

// 升级器不做浏览器 Origin 限制：对等端为桌面/CLI/服务器原生客户端，
// 准入由 hello 帧的节点签名把守（浏览器不是 M3 直传对等端）。
var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(*http.Request) bool { return true },
}

// Handler 返回挂入 HTTP 面的信令端点（GET /v1/channel/{hash}）。
func (h *Hub) Handler() http.HandlerFunc {
	return h.handle
}

func (h *Hub) handle(w http.ResponseWriter, r *http.Request) {
	hash := strings.ToLower(r.PathValue("hash"))
	if !isHex64(hash) {
		http.Error(w, "code_hash 须为 sha256 hex(64 字符)", http.StatusBadRequest)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade 已写错误响应
	}

	// ---- hello 准入（HelloTimeout 内必须完成） ----
	_ = conn.SetReadDeadline(time.Now().Add(h.cfg.HelloTimeout))
	conn.SetReadLimit(int64(h.cfg.MaxFrameBytes)*2 + 4096)
	var hf helloFrame
	if err := conn.ReadJSON(&hf); err != nil || hf.Type != "hello" {
		deny(conn, closeBadHello, "hello 缺失或非法")
		return
	}
	pub, err := registry.ParseNodeID(hf.NodeID)
	if err != nil {
		deny(conn, closeDenied, "node_id 非法")
		return
	}
	if err := registry.VerifySignature(pub, BuildJoinPayload(hf.NodeID, hash, hf.TS), hf.Sig); err != nil {
		deny(conn, closeDenied, "签名校验失败")
		return
	}
	if err := registry.CheckTimestamp(hf.TS, h.now()); err != nil {
		deny(conn, closeDenied, "时间戳过期")
		return
	}
	// 节点须处于有效租约内（准入门槛=与注册 API 同级的身份约束）
	if _, err := h.reg.GetNode(r.Context(), hf.NodeID); err != nil {
		deny(conn, closeDenied, "节点未注册或租约已过期")
		return
	}

	p := &peer{nodeID: hf.NodeID, conn: conn, send: make(chan []byte, 32), done: make(chan struct{})}
	outcome, sess, jerr := h.join(hash, p)
	if jerr != nil {
		h.metrics.SignalingJoin("busy")
		deny(conn, closeBusy, jerr.Error())
		return
	}

	switch outcome {
	case JoinWaiting:
		h.metrics.SignalingJoin("waiting")
		enqueue(p, serverFrame{Type: "waiting"})
	case JoinPaired:
		h.metrics.SignalingJoin("paired")
		other := sess.other(p)
		if other != nil {
			enqueue(p, serverFrame{Type: "paired", PeerID: other.nodeID})
			enqueue(other, serverFrame{Type: "paired", PeerID: p.nodeID})
		}
	}
	go h.writePump(p)
	go h.readPump(sess, p)
}

func deny(conn *websocket.Conn, code int, msg string) {
	_ = conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(code, msg), time.Now().Add(5*time.Second))
	_ = conn.Close()
}

// ---- 双泵 ----

// readPump 读对端帧并转发。协议违规（非 data 帧/超限帧）回 error 帧后断开。
func (h *Hub) readPump(sess *session, p *peer) {
	defer func() { h.leave(sess, p) }()

	// pong 与数据帧均续空闲期；服务端周期 ping（客户端库默认自动回 pong）
	p.conn.SetPongHandler(func(string) error {
		return p.conn.SetReadDeadline(time.Now().Add(h.cfg.IdleTimeout))
	})

	for {
		_ = p.conn.SetReadDeadline(time.Now().Add(h.cfg.IdleTimeout))
		_, raw, err := p.conn.ReadMessage()
		if err != nil {
			return
		}
		var cf clientFrame
		if err := json.Unmarshal(raw, &cf); err != nil || cf.Type != "data" {
			enqueue(p, serverFrame{Type: "error", Message: "仅接受 data 帧"})
			return
		}
		if len(cf.Payload) > h.cfg.MaxFrameBytes {
			enqueue(p, serverFrame{Type: "error", Message: "帧超限"})
			return
		}
		other := sess.other(p)
		if other == nil {
			return // 已被摘除（对方先走）
		}
		envelope, ok := marshalFrame(serverFrame{Type: "data", From: p.nodeID, Payload: cf.Payload})
		if !ok {
			return
		}
		select {
		case other.send <- envelope:
		default:
			return // 对端慢消费，本端退出触发 leave 清理
		}
	}
}

// writePump 出站泵：send 队列 + 周期 ping；done 后冲刷剩余帧再握手关闭。
func (h *Hub) writePump(p *peer) {
	ticker := time.NewTicker(h.cfg.PingPeriod)
	defer ticker.Stop()
	defer func() { _ = p.conn.Close() }()

	write := func(msg []byte) bool {
		_ = p.conn.SetWriteDeadline(time.Now().Add(h.cfg.WriteWait))
		return p.conn.WriteMessage(websocket.TextMessage, msg) == nil
	}
	for {
		select {
		case msg := <-p.send:
			if !write(msg) {
				return
			}
		case <-p.done:
			for {
				select {
				case msg := <-p.send:
					if !write(msg) {
						return
					}
				default:
					_ = p.conn.WriteControl(websocket.CloseMessage,
						websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
						time.Now().Add(h.cfg.WriteWait))
					return
				}
			}
		case <-ticker.C:
			_ = p.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(h.cfg.WriteWait))
		}
	}
}
