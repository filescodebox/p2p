package client

import (
	"fmt"

	pake "github.com/schollz/pake/v3"
)

// pakeCurve PAKE 使用的曲线（croc 同款 SIEC）。
const pakeCurve = "siec"

// runPake 经 exchange 收发 PAKE 消息，返回 32 字节会话密钥。
//
// 轮次语义（schollz/pake v3.2.0 实测锁定，勿"泛化"成循环）：
//
//	发起方(role 0): 发 m1 → 收 m2 → Update(m2) → 密钥就绪
//	响应方(role 1): 收 m1 → Update(m1) → 发 m2 → 密钥就绪
//
// ⚠️ responder 的每次 Update 都会用新随机 α 重新派生 K——只允许 Update 一次；
// 多 Update 会让两侧密钥静默不一致（探针实测）。口令错误不报错，两侧密钥
// 必不相等，差异在传输层首个 AEAD 帧暴露（wire.ErrCorrupt）。
func runPake(pw []byte, initiator bool, exchange func(send []byte) ([]byte, error)) ([]byte, error) {
	role := 1
	if initiator {
		role = 0
	}
	p, err := pake.InitCurve(pw, role, pakeCurve)
	if err != nil {
		return nil, fmt.Errorf("pake 初始化: %w", err)
	}
	if initiator {
		if _, err := exchange(p.Bytes()); err != nil {
			return nil, fmt.Errorf("pake 发送 m1: %w", err)
		}
		m2, err := exchange(nil)
		if err != nil {
			return nil, fmt.Errorf("pake 接收 m2: %w", err)
		}
		if err := p.Update(m2); err != nil {
			return nil, fmt.Errorf("pake 更新: %w", err)
		}
	} else {
		m1, err := exchange(nil)
		if err != nil {
			return nil, fmt.Errorf("pake 接收 m1: %w", err)
		}
		if err := p.Update(m1); err != nil {
			return nil, fmt.Errorf("pake 更新: %w", err)
		}
		if _, err := exchange(p.Bytes()); err != nil {
			return nil, fmt.Errorf("pake 发送 m2: %w", err)
		}
	}
	if !p.HaveSessionKey() {
		return nil, fmt.Errorf("pake 会话密钥未生成")
	}
	key, err := p.SessionKey()
	if err != nil {
		return nil, fmt.Errorf("pake 会话密钥: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("pake 会话密钥长度异常: %d", len(key))
	}
	return key, nil
}
