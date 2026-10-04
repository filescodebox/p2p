package reflect

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestQueryReturnsObservedAddr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	go Serve(ctx, udp, nil)

	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sock.Close() }()

	addr, err := Query(sock, udp.LocalAddr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if addr.Port != sock.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("反射端口应等于套接字本地端口: got %d want %d", addr.Port, sock.LocalAddr().(*net.UDPAddr).Port)
	}
}

func TestIgnoresNonMagic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	go Serve(ctx, udp, nil)

	junk, _ := net.Dial("udp", udp.LocalAddr().String())
	_, _ = junk.Write([]byte("not-magic"))
	time.Sleep(100 * time.Millisecond) // 服务不应崩溃,后续正常请求仍可用

	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sock.Close() }()
	if _, err := Query(sock, udp.LocalAddr().String(), 3*time.Second); err != nil {
		t.Fatalf("垃圾包后应仍可反射: %v", err)
	}
}
