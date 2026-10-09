package relay

import (
	"net"
	"testing"
)

// FuzzReadLine 任意字节流喂首行解析不得 panic、不得超时不返回
// (逐字节读是防 bufio 超读吞帧的关键实现,回归代价高——fuzz 守护)。
func FuzzReadLine(f *testing.F) {
	f.Add([]byte("RELAY 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"))
	f.Add([]byte("RELAY "))
	f.Add([]byte("\n"))
	f.Add([]byte{'R', 'E', 'L', 'A', 'Y', ' '})
	f.Add(make([]byte, maxTokenLen+20))

	f.Fuzz(func(t *testing.T, data []byte) {
		c1, c2 := net.Pipe()
		go func() {
			_, _ = c2.Write(data)
			_ = c2.Close()
		}()
		_, _ = readLine(c1, maxTokenLen) // 任何输入不得 panic
		_ = c1.Close()
	})
}
