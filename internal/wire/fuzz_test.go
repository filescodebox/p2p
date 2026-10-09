package wire

import (
	"net"
	"testing"
)

// FuzzReadMsg 任意入站字节不得 panic;帧解析是网络暴露面,原生 fuzz 挂
// CI 每日短跑防解析类回归(出错形态只可能是 ErrCorrupt 或传输层 io 错误,
// 两者都合法——fuzz 只守护"不失控")。
func FuzzReadMsg(f *testing.F) {
	// 种子:空/截断头/合法形态头/超限长度
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 40, 'S', 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4})
	f.Add(make([]byte, 300))
	f.Add(make([]byte, MaxMessageSize+64)) // 超限长度形态

	f.Fuzz(func(t *testing.T, data []byte) {
		c1, c2 := net.Pipe()
		go func() {
			_, _ = c2.Write(data)
			_ = c2.Close()
		}()
		w, err := New(c1, [32]byte{9}, false)
		if err != nil {
			t.Skip()
		}
		_, _, _ = w.ReadMsg() // 任何输入不得 panic
		_ = c1.Close()
	})
}

// FuzzWriteReadRoundTrip 随机 body 编码→解码必须还原(含边界长度)。
func FuzzWriteReadRoundTrip(f *testing.F) {
	f.Add(uint8(1), []byte("hello"))
	f.Add(uint8(6), make([]byte, 64<<10))
	f.Fuzz(func(t *testing.T, typ byte, body []byte) {
		if len(body)+1 > MaxMessageSize {
			t.Skip()
		}
		c1, c2 := net.Pipe()
		go func() {
			w, err := New(c1, [32]byte{5}, true)
			if err != nil {
				_ = c1.Close()
				return
			}
			_ = w.WriteMsg(typ, body)
			_ = c1.Close()
		}()
		r, err := New(c2, [32]byte{5}, false)
		if err != nil {
			t.Skip()
		}
		gotTyp, gotBody, err := r.ReadMsg()
		_ = c2.Close()
		if err != nil {
			t.Fatalf("合法帧解密失败: %v", err)
		}
		if gotTyp != typ || string(gotBody) != string(body) {
			t.Fatalf("往返不一致: typ=%d len=%d≠%d", gotTyp, len(gotBody), len(body))
		}
	})
}
