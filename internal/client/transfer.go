package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/filescodebox/p2p/internal/wire"
)

// ---- 文件传输协议（wire 消息: meta → ready → chunk* → final）----
// 断点续传 = 接收方以磁盘上既有部分文件的字节数回 ready{offset}，
// 发送方 seek 后续传；最终 sha256 全量校验。

const chunkSize = 64 << 10

type metaMsg struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type readyMsg struct {
	Offset int64 `json:"offset"`
}

type finalMsg struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

var errPeerAborted = errors.New("对端中止传输")

// sendFile 发送文件（发送方= initiator）。
func sendFile(w *wire.Conn, path string, progress func(sent, total int64)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("%s 是目录(单文件传输)", path)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	meta, _ := json.Marshal(metaMsg{Name: filepath.Base(path), Size: st.Size(), SHA256: hex.EncodeToString(hasher.Sum(nil))})
	if err := w.WriteMsg(wire.MsgMeta, meta); err != nil {
		return fmt.Errorf("meta 发送: %w", err)
	}

	msgType, body, err := w.ReadMsg()
	if err != nil {
		return fmt.Errorf("ready 接收: %w", err)
	}
	if msgType != wire.MsgReady {
		return fmt.Errorf("期望 ready 帧,得到 type=%d", msgType)
	}
	var ready readyMsg
	if err := json.Unmarshal(body, &ready); err != nil {
		return fmt.Errorf("ready 解析: %w", err)
	}
	if ready.Offset < 0 || ready.Offset > st.Size() {
		return fmt.Errorf("对端 offset 非法: %d", ready.Offset)
	}
	if _, err := f.Seek(ready.Offset, io.SeekStart); err != nil {
		return err
	}

	sent := ready.Offset
	buf := make([]byte, chunkSize)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := w.WriteMsg(wire.MsgChunk, buf[:n]); err != nil {
				return fmt.Errorf("chunk 发送: %w", err)
			}
			sent += int64(n)
			if progress != nil {
				progress(sent, st.Size())
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}

	msgType, body, err = w.ReadMsg()
	if err != nil {
		return fmt.Errorf("final 接收: %w", err)
	}
	if msgType != wire.MsgFinal {
		return fmt.Errorf("期望 final 帧,得到 type=%d", msgType)
	}
	var fin finalMsg
	if err := json.Unmarshal(body, &fin); err != nil {
		return fmt.Errorf("final 解析: %w", err)
	}
	if !fin.OK {
		return fmt.Errorf("对端校验失败: %s", fin.Message)
	}
	return nil
}

// recvFile 接收文件到 dir（含既有部分文件断点续传）。
func recvFile(w *wire.Conn, dir string, progress func(got, total int64)) (string, error) {
	msgType, body, err := w.ReadMsg()
	if err != nil {
		return "", fmt.Errorf("meta 接收: %w", err)
	}
	if msgType != wire.MsgMeta {
		return "", fmt.Errorf("期望 meta 帧,得到 type=%d", msgType)
	}
	var meta metaMsg
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", fmt.Errorf("meta 解析: %w", err)
	}
	if meta.Name == "" || meta.Size < 0 {
		return "", fmt.Errorf("meta 非法: %+v", meta)
	}
	out := filepath.Join(dir, filepath.Base(meta.Name))

	offset := int64(0)
	if fi, err := os.Stat(out); err == nil && !fi.IsDir() && fi.Size() <= meta.Size {
		offset = fi.Size() // 断点续传起点
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	hasher := sha256.New()
	// 既有前缀纳入校验(从磁盘读回)
	if offset > 0 {
		prefix, err := os.ReadFile(out)
		if err != nil || int64(len(prefix)) != offset {
			// 读取失败或长度对不上则从头再来
			offset = 0
			hasher.Reset()
		} else {
			hasher.Write(prefix)
		}
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return "", err
	}
	if err := f.Truncate(offset); err != nil {
		return "", err
	}

	rd, _ := json.Marshal(readyMsg{Offset: offset})
	if err := w.WriteMsg(wire.MsgReady, rd); err != nil {
		return "", fmt.Errorf("ready 发送: %w", err)
	}

	got := offset
	for got < meta.Size {
		msgType, body, err := w.ReadMsg()
		if err != nil {
			return "", fmt.Errorf("chunk 接收: %w", err)
		}
		if msgType != wire.MsgChunk {
			return "", fmt.Errorf("期望 chunk 帧,得到 type=%d", msgType)
		}
		if _, err := f.Write(body); err != nil {
			return "", err
		}
		hasher.Write(body)
		got += int64(len(body))
		if progress != nil {
			progress(got, meta.Size)
		}
	}

	sum := hex.EncodeToString(hasher.Sum(nil))
	fin := finalMsg{OK: sum == meta.SHA256}
	if !fin.OK {
		fin.Message = fmt.Sprintf("sha256 不匹配(期望 %s 实际 %s)", meta.SHA256, sum)
	}
	rd, _ = json.Marshal(fin)
	if err := w.WriteMsg(wire.MsgFinal, rd); err != nil {
		return "", err
	}
	if !fin.OK {
		return "", errors.New(fin.Message)
	}
	return out, nil
}
