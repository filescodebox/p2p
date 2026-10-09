package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
)

// BenchmarkRelayThroughput 中继单信道吞吐(双向各 32MB,默认无限速):
// 线路=本机 TCP,测的是管道/限速器/拷贝开销,不含真实网络。
func BenchmarkRelayThroughput(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	go func() { _ = Serve(ctx, ln, Params{}) }()
	b.Cleanup(func() { _ = ln.Close() })

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		b.Fatal(err)
	}
	tok := hex.EncodeToString(token)

	dial := func() net.Conn {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := conn.Write([]byte("RELAY " + tok + "\n")); err != nil {
			b.Fatal(err)
		}
		return conn
	}
	a := dial()
	b.Cleanup(func() { _ = a.Close() })
	bb := dial()
	b.Cleanup(func() { _ = bb.Close() })

	payload := make([]byte, 64<<10) // 64KB/写
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}
	// 接收侧排空
	go func() {
		_, _ = io.Copy(io.Discard, bb)
	}()

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	// 不等对端排空完整(基准看发送侧吞吐);停止时 Cleanup 关闭连接
	b.StopTimer()
}
