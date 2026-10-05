// Package wire 提供传输无关的 AEAD 消息帧：QUIC 流与中继 TCP 共用同一条
// 消息语义，上层传输逻辑（打洞成功/中继兜底）不感知差异。
//
// 线上格式（大端）：
//
//	u32(len) || nonce(12) || ciphertext
//	plaintext = type(1) || body(len-type-1)
//
// 密钥来自 PAKE 会话密钥派生（k_data）；无密钥者既不能读也不能产生合法帧——
// 首帧即完成双向认证（中继路径无 TLS，靠它防令牌窃用）。
package wire

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// 消息类型（M3 传输协议）。
const (
	MsgMeta  byte = 1 // 发送方→接收方：JSON {name,size,sha256}
	MsgReady byte = 2 // 接收方→发送方：JSON {offset}（断点续传起点）
	MsgChunk byte = 3 // 发送方→接收方：原始文件字节
	MsgFinal byte = 4 // 接收方→发送方：JSON {ok,message}
)

// MaxMessageSize 单条消息明文上限（chunk 64KB + 头部裕量）。
const MaxMessageSize = 256 << 10

// ErrCorrupt 帧无法解密/格式非法（对端无密钥或流被破坏）。
var ErrCorrupt = errors.New("wire: 帧校验失败")

// Conn 消息化连接。
type Conn struct {
	rw   io.ReadWriter
	aead cipher.AEAD
	seq  uint64 // 发送序号，作为 nonce 前缀 material

	// dirTag/peerTag 方向标签（nonce 首字节）。2026-10-05 审计 P1 修复：
	// 此前两侧共用同一 data 密钥且 seq 均从 0 起算——发送方首帧 MsgMeta 与
	// 接收方首帧 MsgReady 的 key+nonce 完全相同（中继路径明文 TCP 上密钥流
	// 重用泄漏双向明文异或；Poly1305 一次性密钥重用可伪造合法帧）。现约定
	// 发送侧写 dirSend/读 dirRecv，接收侧写 dirRecv/读 dirSend，双向 nonce
	// 空间恒不相交。
	dirTag  byte
	peerTag byte
}

// 方向标签取可打印 ASCII，便于抓包排查；无密码学含义（仅分离 nonce 空间）。
const (
	dirSend byte = 'S' // 发送方→接收方方向的帧
	dirRecv byte = 'R' // 接收方→发送方方向的帧
)

// New 以 32 字节会话密钥构造；isSender 标明本端角色（发送侧/接收侧），
// 决定本端出站帧的方向标签。
func New(rw io.ReadWriter, key [32]byte, isSender bool) (*Conn, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("wire: %w", err)
	}
	dir, peer := dirSend, dirRecv
	if !isSender {
		dir, peer = dirRecv, dirSend
	}
	return &Conn{rw: rw, aead: aead, dirTag: dir, peerTag: peer}, nil
}

// DeriveKey 从 PAKE 会话密钥按用途派生子密钥（HKDF-SHA256，salt 空即
// hash-len 零串，info 绑定用途标签与协议域）。2026-10-05 审计 P3：原实现为
// sha256(session||label) 裸拼接，已按最佳实践换 HKDF；输出随本变更整体
// 轮换（与方向标签 nonce 修复同属传输协议破坏性变更，客户端须同版升级）。
func DeriveKey(session []byte, label string) [32]byte {
	out, err := hkdf.Key(sha256.New, session, nil, "fcb-p2p/v2/"+label, 32)
	if err != nil || len(out) != 32 {
		// HKDF-SHA256 输出 32B 不会失败；防御性兜底
		sum := sha256.Sum256(session)
		return sum
	}
	var k [32]byte
	copy(k[:], out)
	return k
}

// WriteMsg 编码、加密并写出一条消息。
func (c *Conn) WriteMsg(msgType byte, body []byte) error {
	if len(body)+1 > MaxMessageSize {
		return fmt.Errorf("wire: 消息超限 %d", len(body)+1)
	}
	plaintext := make([]byte, 0, len(body)+1)
	plaintext = append(plaintext, msgType)
	plaintext = append(plaintext, body...)

	nonce := make([]byte, chacha20poly1305.NonceSize)
	nonce[0] = c.dirTag
	binary.BigEndian.PutUint64(nonce[4:], c.seq)
	c.seq++

	ct := c.aead.Seal(nil, nonce, plaintext, nil)
	head := make([]byte, 4)
	binary.BigEndian.PutUint32(head, uint32(len(nonce)+len(ct)))

	if _, err := c.rw.Write(head); err != nil {
		return err
	}
	if _, err := c.rw.Write(nonce); err != nil {
		return err
	}
	_, err := c.rw.Write(ct)
	return err
}

// ReadMsg 读取并解密一条消息。
func (c *Conn) ReadMsg() (byte, []byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(c.rw, head[:]); err != nil {
		return 0, nil, err
	}
	total := binary.BigEndian.Uint32(head[:])
	if total < chacha20poly1305.NonceSize+16 || total > MaxMessageSize+chacha20poly1305.NonceSize+16 {
		return 0, nil, ErrCorrupt
	}
	buf := make([]byte, total)
	if _, err := io.ReadFull(c.rw, buf); err != nil {
		return 0, nil, err
	}
	nonce, ct := buf[:chacha20poly1305.NonceSize], buf[chacha20poly1305.NonceSize:]
	// 入站帧必须携带对端方向标签：错标签=密钥不一致或流错乱，直接拒
	// （错口令场景本就在 AEAD Open 处暴露，此处提前到标签位）
	if nonce[0] != c.peerTag {
		return 0, nil, ErrCorrupt
	}
	plaintext, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return 0, nil, ErrCorrupt
	}
	return plaintext[0], plaintext[1:], nil
}
