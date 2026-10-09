package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pigeonbox/p2p/internal/wire"
)

// ---- 文件传输协议 ----
//
// v2 帧序: meta → ready{offset} → chunk* → final(全部走同一条流)。
// v3 追加: ready 后控制流可再发 plan{streams}; streams>0 时发送方再开
// streams 条数据流,每条先发 seg{start} 再连续 chunk,发完即关流(FIN)。
// 数据流按剩余区间连续等分,互不重叠;多流模式下控制流只承载信令帧。
//
// 断点续传 = 接收方以磁盘上既有部分文件的字节数回 ready{offset},发送方
// seek 后续传;多流仅在 offset==0(全新传输)时启用——续传路径保持 v2 顺序
// 写语义,避免半成品多流文件含零洞后被错误续传。最终 sha256 全量校验不变,
// 校验失败删除半成品。

const chunkSize = 64 << 10

// 多流阈值与并行度:小文件走单流(建流开销不值);高 BDP 链路(跨国)下单流
// 吞吐受限,QUIC 多路复用 2-4 流即可吃满常见带宽。
const (
	minMultiStreamSize = 8 << 20
	maxDataStreams     = 3
	segOpenBudget      = 10 * time.Second
)

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

// planMsg 多流计划:发送方宣告将打开的数据流条数(0=单流,兼容中继路径)。
type planMsg struct {
	Streams int `json:"streams"`
}

// segMsg 数据流首帧:本流承载的起始偏移。
type segMsg struct {
	Start int64 `json:"start"`
}

var errPeerAborted = errors.New("对端中止传输")

// sendFile 发送文件（发送方= initiator）。
func sendFile(x *xport, path string, progress func(sent, total int64)) error {
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
	if err := x.ctrl.WriteMsg(wire.MsgMeta, meta); err != nil {
		return fmt.Errorf("meta 发送: %w", err)
	}

	msgType, body, err := x.ctrl.ReadMsg()
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

	// 多流判据:QUIC 直传 && 全新传输 && 剩余量够大(续传恒单流,见文件头注释)
	remaining := st.Size() - ready.Offset
	if x.open != nil && ready.Offset == 0 && remaining >= minMultiStreamSize {
		return sendFileMulti(x, f, st.Size(), progress)
	}

	// 单流路径(v2 语义):顺序 seek + chunk + final
	if _, err := f.Seek(ready.Offset, io.SeekStart); err != nil {
		return err
	}
	sent := ready.Offset
	buf := make([]byte, chunkSize)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := x.ctrl.WriteMsg(wire.MsgChunk, buf[:n]); err != nil {
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
	return awaitFinal(x.ctrl)
}

// sendFileMulti v3 多流并行:plan 宣告 → 开 N 条数据流连续切段 → 等全部
// 写完 → 控制流 final 握手。任一数据流失败即取消其余并整体报错。
func sendFileMulti(x *xport, f *os.File, size int64, progress func(sent, total int64)) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	plan, _ := json.Marshal(planMsg{Streams: maxDataStreams})
	if err := x.ctrl.WriteMsg(wire.MsgPlan, plan); err != nil {
		return fmt.Errorf("plan 发送: %w", err)
	}

	// 连续等分区间;整除余数归末段
	boundaries := make([]int64, maxDataStreams+1)
	for i := 0; i <= maxDataStreams; i++ {
		boundaries[i] = size * int64(i) / int64(maxDataStreams)
	}

	openCtx, openCancel := context.WithTimeout(ctx, segOpenBudget)
	conns := make([]*wire.Conn, maxDataStreams)
	for i := 0; i < maxDataStreams; i++ {
		c, err := x.open(openCtx, i)
		if err != nil {
			openCancel()
			cancel()
			return fmt.Errorf("建立数据流: %w", err)
		}
		conns[i] = c
	}
	openCancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 1)
	for i := 0; i < maxDataStreams; i++ {
		wg.Add(1)
		go func(i int, start, end int64) {
			defer wg.Done()
			if err := writeSegment(ctx, conns[i], f, start, end); err != nil {
				select {
				case errCh <- fmt.Errorf("seg%d: %w", i, err):
				default:
				}
				cancel() // 一处失败,整体速断
			}
		}(i, boundaries[i], boundaries[i+1])
	}

	// 进度:多写方并发推进,聚合后由单 goroutine 上报(progress 非并发安全)
	var sent atomic.Int64
	stopProgress := make(chan struct{})
	if progress != nil {
		go func() {
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-stopProgress:
					progress(sent.Load(), size)
					return
				case <-t.C:
					progress(sent.Load(), size)
				}
			}
		}()
	}
	wg.Wait()
	close(stopProgress)
	select {
	case err := <-errCh:
		return err
	default:
	}
	return awaitFinal(x.ctrl)
}

// writeSegment 单数据流:seg 首帧 + 区间 chunk + 关流(FIN)。
// ReadAt 并发安全(等价 pread),多流共享同一源文件句柄。
// ⚠️ 末尾必须关流——接收方以流 FIN 为段结束信号,不关即双方互等死锁。
func writeSegment(ctx context.Context, c *wire.Conn, f *os.File, start, end int64) error {
	defer func() { _ = c.Close() }()
	seg, _ := json.Marshal(segMsg{Start: start})
	if err := c.WriteMsg(wire.MsgSeg, seg); err != nil {
		return fmt.Errorf("seg 帧: %w", err)
	}
	buf := make([]byte, chunkSize)
	for pos := start; pos < end; {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n := int64(len(buf))
		if remain := end - pos; remain < n {
			n = remain
		}
		if _, err := f.ReadAt(buf[:n], pos); err != nil {
			return fmt.Errorf("读源文件: %w", err)
		}
		if err := c.WriteMsg(wire.MsgChunk, buf[:n]); err != nil {
			return fmt.Errorf("chunk 发送: %w", err)
		}
		pos += n
	}
	return nil
}

// awaitFinal 控制流 final 握手(发送侧收尾)。
func awaitFinal(ctrl *wire.Conn) error {
	msgType, body, err := ctrl.ReadMsg()
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

// recvFile 接收文件到 dir（含既有部分文件断点续传;多流仅全新传输启用）。
func recvFile(x *xport, dir string, progress func(got, total int64)) (string, error) {
	msgType, body, err := x.ctrl.ReadMsg()
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
	// 0600 落盘（2026-10-05 审计 P3：传输文件默认私密，0644 让多用户主机上
	// 其他本地用户可读）
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY, 0o600)
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
	if err := x.ctrl.WriteMsg(wire.MsgReady, rd); err != nil {
		return "", fmt.Errorf("ready 发送: %w", err)
	}

	// 计划帧(v2 对端不发 plan 直接发 chunk——兼容分支)
	msgType, body, err = x.ctrl.ReadMsg()
	if err != nil {
		return "", fmt.Errorf("plan 接收: %w", err)
	}
	streams := 0
	if msgType == wire.MsgPlan {
		var plan planMsg
		if err := json.Unmarshal(body, &plan); err != nil {
			return "", fmt.Errorf("plan 解析: %w", err)
		}
		if plan.Streams < 0 || plan.Streams > 64 {
			return "", fmt.Errorf("plan.streams 非法: %d", plan.Streams)
		}
		streams = plan.Streams
	} else if msgType != wire.MsgChunk {
		return "", fmt.Errorf("期望 plan/chunk 帧,得到 type=%d", msgType)
	}

	if streams > 0 {
		if offset != 0 {
			return "", errors.New("对端在续传场景宣告多流(协议不一致),中止")
		}
		return recvFileMulti(x, f, out, meta, streams, progress)
	}

	// 单流路径(v2 语义;msgType 非 plan 时已是首个 chunk)
	got := offset
	if msgType == wire.MsgChunk {
		if _, err := f.Write(body); err != nil {
			return "", err
		}
		hasher.Write(body)
		got += int64(len(body))
		if progress != nil {
			progress(got, meta.Size)
		}
	}
	for got < meta.Size {
		msgType, body, err = x.ctrl.ReadMsg()
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
	return finishRecv(x.ctrl, f, out, meta, hasher)
}

// recvFileMulti v3 多流接收:accept N 条数据流并发落盘(WriteAt 定位写),
// 全部完成后控制流 final 握手。多流模式仅全新传输(offset==0),hasher 为空。
// 流配对依据 QUIC accept 顺序与 open 顺序一致(stream id 单调):worker i
// 用 segKeyLabel(i) 派生密钥,并校验 seg 帧起始偏移与本地等分边界一致。
func recvFileMulti(x *xport, f *os.File, out string, meta metaMsg, streams int, progress func(got, total int64)) (string, error) {
	// 与发送方同公式的连续等分边界
	boundaries := make([]int64, streams+1)
	for i := 0; i <= streams; i++ {
		boundaries[i] = meta.Size * int64(i) / int64(streams)
	}

	var got atomic.Int64
	errCh := make(chan error, 1)
	stopProgress := make(chan struct{})
	if progress != nil {
		go func() {
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-stopProgress:
					progress(got.Load(), meta.Size)
					return
				case <-t.C:
					progress(got.Load(), meta.Size)
				}
			}
		}()
	}

	accCtx, cancelAcc := context.WithTimeout(context.Background(), segOpenBudget)
	defer cancelAcc()

	// 串行 accept:并发调用 AcceptStream 时,流的 FIFO 派发给"先到的调用"
	// 而非"第 i 个 worker",会造成 worker 与数据流错配(密钥按序号派生即
	// 解密失败)。先按序收齐全部数据流,再并发消费。
	conns := make([]*wire.Conn, streams)
	for i := 0; i < streams; i++ {
		c, err := x.accept(accCtx, i)
		if err != nil {
			for _, oc := range conns[:i] {
				_ = oc.Close()
			}
			_ = f.Close()
			_ = os.Remove(out)
			return "", fmt.Errorf("seg%d accept: %w", i, err)
		}
		conns[i] = c
	}

	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(i int, start, end int64) {
			defer wg.Done()
			if err := recvSegment(conns[i], f, start, end, &got); err != nil {
				select {
				case errCh <- fmt.Errorf("seg%d: %w", i, err):
				default:
				}
			}
		}(i, boundaries[i], boundaries[i+1])
	}
	wg.Wait()
	close(stopProgress)
	select {
	case err := <-errCh:
		_ = f.Close()
		_ = os.Remove(out) // 失败即清,不留多流零洞半成品
		return "", err
	default:
	}
	// ⚠️ 多流乱序到达,增量 hasher 的输入序≠文件字节序(sha256 不可交换),
	// 全量校验必须以盘上内容定稿——与断点续传读回前缀同一思路。
	if err := f.Sync(); err != nil {
		return "", err
	}
	rd, err := os.Open(out)
	if err != nil {
		return "", err
	}
	final := sha256.New()
	_, copyErr := io.Copy(final, rd)
	_ = rd.Close()
	if copyErr != nil {
		return "", fmt.Errorf("全量校验读回: %w", copyErr)
	}
	return finishRecv(x.ctrl, f, out, meta, final)
}

// recvSegment 单数据流:校验 seg 起始 → chunk 落盘至流 FIN。
func recvSegment(c *wire.Conn, f *os.File, start, end int64, got *atomic.Int64) error {
	defer func() { _ = c.Close() }()

	msgType, body, err := c.ReadMsg()
	if err != nil {
		return fmt.Errorf("seg 帧接收: %w", err)
	}
	if msgType != wire.MsgSeg {
		return fmt.Errorf("期望 seg 帧,得到 type=%d", msgType)
	}
	var sm segMsg
	if err := json.Unmarshal(body, &sm); err != nil {
		return fmt.Errorf("seg 解析: %w", err)
	}
	if sm.Start != start {
		return fmt.Errorf("seg 起始不符: 期望 %d 实际 %d", start, sm.Start)
	}

	pos := start
	for {
		msgType, body, err = c.ReadMsg()
		if err != nil {
			// 发送方发完本段即关流:干净 EOF=正常收尾,其余(截断帧/重置)皆错
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("chunk 接收: %w", err)
		}
		if msgType != wire.MsgChunk {
			return fmt.Errorf("期望 chunk 帧,得到 type=%d", msgType)
		}
		if _, err := f.WriteAt(body, pos); err != nil {
			return err
		}
		pos += int64(len(body))
		got.Add(int64(len(body)))
		if pos > end {
			return fmt.Errorf("段越界: 已写 %d 超过边界 %d", pos, end)
		}
	}
	if pos != end {
		return fmt.Errorf("段不完整: %d/%d 字节", pos-start, end-start)
	}
	return nil
}

// finishRecv 接收侧收尾:sha256 全量校验 + final 握手 + 坏内容清理。
func finishRecv(ctrl *wire.Conn, f *os.File, out string, meta metaMsg, hasher hash.Hash) (string, error) {
	sum := hex.EncodeToString(hasher.Sum(nil))
	fin := finalMsg{OK: sum == meta.SHA256}
	if !fin.OK {
		fin.Message = fmt.Sprintf("sha256 不匹配(期望 %s 实际 %s)", meta.SHA256, sum)
	}
	rd, _ := json.Marshal(fin)
	if err := ctrl.WriteMsg(wire.MsgFinal, rd); err != nil {
		return "", err
	}
	if !fin.OK {
		// 校验失败删除半成品（2026-10-05 审计 P3：坏内容不再以正式文件名残留）
		_ = f.Close()
		_ = os.Remove(out)
		return "", errors.New(fin.Message)
	}
	return out, nil
}
