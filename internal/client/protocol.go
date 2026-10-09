// 传输协议版本协商(v3 起):配对完成后、PAKE 之前,双方经信令信道显式
// 交换协议版本。此前"破坏性变更须客户端同版"只靠行为约定,版本不一致
// 表现为 AEAD 帧解密失败的密码学报错(wire.ErrCorrupt),用户无从判断;
// 显式协商后给出可读错误。版本帧走信令信道的明文 data——它只服务可诊断性,
// 不承担认证职责(认证仍由 PAKE+传输层首帧 AEAD 把守,信令侧另有节点签名
// 准入),篡改它的最坏结果是传输失败,不构成降权。
package client

import (
	"encoding/json"
	"fmt"
)

// protoVersion 当前直传传输协议版本。
//
//	v2 (2026-10-05): 方向标签 nonce 分离+HKDF 派生(破坏性,双端同版)
//	v3 (2026-10-09): +显式版本协商;QUIC 直传多流并行分段(relay 路径帧格式不变)
//	v4 (2026-10-09): 多文件 manifest 流(逐文件授权/zstd 压缩/单遍哈希/
//	                  文件边界换源升级);帧上限 1MB(压缩批量)
const protoVersion = 4

// negotiateVersion 双方互换协议版本帧。两侧先发后收:信令信道双向独立
// 排队,不会互等死锁;帧序 FIFO 保证先收到对方的版本帧再进入 PAKE。
func negotiateVersion(ch *channel) error {
	payload, err := json.Marshal(map[string]int{"proto": protoVersion})
	if err != nil {
		return err
	}
	if err := ch.send(payload); err != nil {
		return fmt.Errorf("协议版本发送: %w", err)
	}
	raw, err := ch.recv()
	if err != nil {
		return fmt.Errorf("协议版本接收: %w", err)
	}
	var peer struct {
		Proto int `json:"proto"`
	}
	if err := json.Unmarshal(raw, &peer); err != nil || peer.Proto == 0 {
		return fmt.Errorf("对端不支持协议协商(传输协议 v2 及以下),两端请升级到同版 p2pc")
	}
	if peer.Proto != protoVersion {
		return fmt.Errorf("传输协议版本不一致: 本端 v%d,对端 v%d——请两端升级到同版 p2pc", protoVersion, peer.Proto)
	}
	return nil
}
