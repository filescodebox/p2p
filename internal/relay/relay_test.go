package relay

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
)

func dialToken(t *testing.T, addr, token string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("RELAY " + token + "\n")); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestPairingPipesBothWays(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = Serve(ctx, ln, Params{}) }()
	t.Cleanup(func() { _ = ln.Close() })

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(raw)

	a := dialToken(t, ln.Addr().String(), token)
	defer func() { _ = a.Close() }()
	b := dialToken(t, ln.Addr().String(), token)
	defer func() { _ = b.Close() }()

	// A→B
	if _, err := a.Write([]byte("ping-from-a")); err != nil {
		t.Fatal(err)
	}
	_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, 11)
	if _, err := ioReadFull(b, got); err != nil {
		t.Fatalf("B 收 A: %v", err)
	}
	if string(got) != "ping-from-a" {
		t.Fatalf("B 收到 %q", got)
	}
	// B→A
	if _, err := b.Write([]byte("pong-from-b")); err != nil {
		t.Fatal(err)
	}
	_ = a.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := ioReadFull(a, got[:11]); err != nil {
		t.Fatalf("A 收 B: %v", err)
	}
	if string(got[:11]) != "pong-from-b" {
		t.Fatalf("A 收到 %q", got[:11])
	}
}

func TestBadLineDisconnects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = Serve(ctx, ln, Params{}) }()
	t.Cleanup(func() { _ = ln.Close() })

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := bufio.NewReader(conn).ReadByte(); err == nil {
		t.Fatal("非法首行应被断开")
	} else if !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "closed") {
		t.Fatalf("断开方式异常: %v", err)
	}
}

func ioReadFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
