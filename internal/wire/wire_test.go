package wire

import (
	"bytes"
	"net"
	"testing"
)

// 双向帧互通回归：发送侧/接收侧角色配对后可正常收发（2026-10-05 审计 P1
// 修复——方向标签分离 nonce 空间，防同密钥跨方向 nonce 重用）。
func TestDirectionalFramesRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()

	key := [32]byte{1}
	snd, err := New(a, key, true)
	if err != nil {
		t.Fatalf("发送侧构造: %v", err)
	}
	rcv, err := New(b, key, false)
	if err != nil {
		t.Fatalf("接收侧构造: %v", err)
	}

	// net.Pipe 为同步无缓冲管道：写端会阻塞到对端读，读写必须并发
	errCh := make(chan error, 1)
	go func() { errCh <- snd.WriteMsg(MsgMeta, []byte(`{"name":"a.txt"}`)) }()
	typ, body, err := rcv.ReadMsg()
	if err != nil || typ != MsgMeta || string(body) != `{"name":"a.txt"}` {
		t.Fatalf("接收侧读帧: typ=%d body=%q err=%v", typ, body, err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("发送侧写帧: %v", err)
	}

	go func() { errCh <- rcv.WriteMsg(MsgReady, []byte(`{"offset":0}`)) }()
	typ, body, err = snd.ReadMsg()
	if err != nil || typ != MsgReady || string(body) != `{"offset":0}` {
		t.Fatalf("发送侧读帧: typ=%d body=%q err=%v", typ, body, err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("接收侧写帧: %v", err)
	}
}

// 同向标签不入站：接收侧读到自己方向的帧必须拒绝（方向空间不相交的守卫）。
func TestWrongDirectionTagRejected(t *testing.T) {
	var buf bytes.Buffer
	key := [32]byte{2}
	rcv, err := New(&nopWriteReader{buf: &buf}, key, false)
	if err != nil {
		t.Fatalf("构造: %v", err)
	}
	// 用同角色（接收侧）Conn 造一帧——dirTag=dirRecv，对 rcv 而非对端方向
	rogue, _ := New(&nopWriteReader{buf: &buf}, key, false)
	if err := rogue.WriteMsg(MsgMeta, []byte("x")); err != nil {
		t.Fatalf("造帧: %v", err)
	}
	if _, _, err := rcv.ReadMsg(); err == nil {
		t.Fatal("同方向标签帧应被拒绝，实际通过")
	}
}

// nopWriteReader 只出的 ReadWriter（Write 进 bytes.Buffer，Read 恒 EOF——
// 本测试只需 Write 侧生效）。
type nopWriteReader struct{ buf *bytes.Buffer }

func (n *nopWriteReader) Write(p []byte) (int, error) { return n.buf.Write(p) }
func (n *nopWriteReader) Read([]byte) (int, error)    { return 0, net.ErrClosed }
