package client

import (
	"log/slog"
	"path/filepath"
	"testing"
)

func TestDebugLoopback(t *testing.T) {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	f := newFixture(t, false)
	code, _ := GenerateCode()
	sendDir := t.TempDir()
	recvDir := t.TempDir()
	src := randomFile(t, sendDir, "dbg.bin", 256<<10)

	errCh := make(chan error, 1)
	go func() {
		opts := testOpts(f, "send")
		opts.Quiet = false
		opts.NodeKeyPath = filepath.Join(t.TempDir(), "k")
		c, err := New(opts)
		if err != nil {
			errCh <- err
			return
		}
		_, err = c.Send(src, code)
		errCh <- err
	}()
	waitForAnnounce(t, f.base, code)
	ropts := testOpts(f, "recv")
	ropts.Quiet = false
	c, err := New(ropts)
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Receive(code, recvDir)
	t.Logf("receiver: out=%s err=%v", out, err)
	t.Logf("sender err: %v", <-errCh)
}
