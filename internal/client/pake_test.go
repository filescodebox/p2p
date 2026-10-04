package client

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

// errPakeStall 交换信道超时（探针脚手架用）。
var errPakeStall = errors.New("pake 交换停滞")

// TestPakeKeyAgreement 验证轮次语义与密钥一致性：
// 双方经内存信道跑完整 PAKE，口令一致→密钥一致；口令不同→报错。
func TestPakeKeyAgreement(t *testing.T) {
	run := func(pwA, pwB []byte) (keyA, keyB []byte, errA, errB error) {
		chanA := make(chan []byte, 8) // A 收
		chanB := make(chan []byte, 8) // B 收
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			keyA, errA = runPake(pwA, true, func(send []byte) ([]byte, error) {
				if send != nil {
					chanB <- send
					return nil, nil
				}
				return recvChan(chanA)
			})
		}()
		go func() {
			defer wg.Done()
			keyB, errB = runPake(pwB, false, func(send []byte) ([]byte, error) {
				if send != nil {
					chanA <- send
					return nil, nil
				}
				return recvChan(chanB)
			})
		}()
		wg.Wait()
		return
	}

	t.Run("口令一致", func(t *testing.T) {
		keyA, keyB, errA, errB := run([]byte("shared-passcode-123456"), []byte("shared-passcode-123456"))
		if errA != nil || errB != nil {
			t.Fatalf("PAKE 失败: errA=%v errB=%v", errA, errB)
		}
		if len(keyA) != 32 {
			t.Fatalf("会话密钥应 32 字节,得到 %d", len(keyA))
		}
		if !bytes.Equal(keyA, keyB) {
			t.Fatal("两侧会话密钥不一致")
		}
	})

	t.Run("口令不一致", func(t *testing.T) {
		// PAKE 对错口令不报错：两侧各自派生密钥但必不相等，
		// 差异在传输层首个 AEAD 帧暴露（安全语义，见 runPake 注释）
		keyA, keyB, errA, errB := run([]byte("pass-A-1234567890"), []byte("pass-B-1234567890"))
		if errA != nil || errB != nil {
			t.Fatalf("错口令不应报错(应密钥不一致): errA=%v errB=%v", errA, errB)
		}
		if bytes.Equal(keyA, keyB) {
			t.Fatal("错口令两侧密钥不应相等")
		}
	})
}

// recvChan 带超时的阻塞收（模拟真实信道语义）。
func recvChan(ch chan []byte) ([]byte, error) {
	select {
	case b := <-ch:
		return b, nil
	case <-time.After(5 * time.Second):
		return nil, errPakeStall
	}
}
