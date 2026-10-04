package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/filescodebox/p2p/internal/wire"
)

// ---- 传输建立：打洞成功走 QUIC(打洞套接字),失败走中继 TCP ----

const quicALPN = "fcb-p2p/1"

// relayToken 由会话密钥派生的中继信道凭据（无口令不可计算;窃取仅构成 DoS——
// 传输层首帧 AEAD 认证,攻击者产不出合法帧）。
func relayToken(session []byte) string {
	k := wire.DeriveKey(session, "relay")
	return hex.EncodeToString(k[:])
}

// sessionCert 生成会话级临时自签证书（P-256,2h 有效;指纹经 PAKE 加密信道
// 交换,QUIC 握手双向按指纹钉定——无指纹者握手必败）。
func sessionCert() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "fcb-p2p-session"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	fpBytes := sha256.Sum256(der)
	fp := hex.EncodeToString(fpBytes[:])
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, fp, nil
}

// verifyFP 证书指纹钉定校验器（替代链式校验——只认 PAKE 加密信道里
// 交换过的那张证书,信任锚=口令本身）。
func verifyFP(want string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("对端未出示证书")
		}
		sum := sha256.Sum256(rawCerts[0])
		if hex.EncodeToString(sum[:]) != want {
			return fmt.Errorf("对端证书指纹不匹配")
		}
		return nil
	}
}

// establishQUIC 在打洞成功的 UDP 套接字上建立 QUIC 传输。
// sender 作为服务端监听;receiver 拨号 punch 验证过的对端地址。
// 套接字交给 quic.Transport 后不得再用于原始读写(打洞循环须已停止)。
// 返回消息化连接与清理函数。
func establishQUIC(sock *net.UDPConn, session []byte, cert tls.Certificate, peerFP string, remote *net.UDPAddr, isSender bool) (*wire.Conn, func(), error) {
	tlsBase := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{quicALPN},
	}
	if isSender {
		tlsBase.ClientAuth = tls.RequireAnyClientCert
	} else {
		tlsBase.InsecureSkipVerify = true // 证书校验由指纹钉定承担
	}
	tlsBase.VerifyPeerCertificate = verifyFP(peerFP)
	qcfg := &quic.Config{
		MaxIdleTimeout:       60 * time.Second,
		HandshakeIdleTimeout: 10 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
	}
	if qlogDir := os.Getenv("FCB_P2P_QLOG"); qlogDir != "" {
		_ = os.MkdirAll(qlogDir, 0o755)
		role := "server"
		if !isSender {
			role = "client"
		}
		qcfg.Tracer = func(_ context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
			f, _ := os.Create(filepath.Join(qlogDir, role+"-"+connID.String()+".qlog"))
			return qlogwriter.NewConnectionFileSeq(f, isClient, connID, []string{qlog.EventSchema})
		}
	}
	tr := &quic.Transport{Conn: sock}

	// 流方向: 发送方(QUIC 服务端)打开流并率先写 meta——QUIC 流在首字节
	// 上线前对端 AcceptStream 不会返回,故接收方以"收到 meta 帧"为准,
	// 不存在空等;错口令在首个 AEAD 帧解密处暴露。
	opCtx, opCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer opCancel()
	var stream *quic.Stream
	if isSender {
		ln, err := tr.Listen(tlsBase, qcfg)
		if err != nil {
			return nil, nil, fmt.Errorf("quic 监听: %w", err)
		}
		qc, err := ln.Accept(opCtx)
		if err != nil {
			_ = tr.Close()
			return nil, nil, fmt.Errorf("quic 接受连接: %w", err)
		}
		stream, err = qc.OpenStreamSync(opCtx)
		if err != nil {
			_ = tr.Close()
			return nil, nil, fmt.Errorf("quic 打开流: %w", err)
		}
	} else {
		qc, err := tr.Dial(opCtx, remote, tlsBase, qcfg)
		if err != nil {
			_ = tr.Close()
			return nil, nil, fmt.Errorf("quic 拨号: %w", err)
		}
		stream, err = qc.AcceptStream(opCtx)
		if err != nil {
			_ = tr.Close()
			return nil, nil, fmt.Errorf("quic 接受流: %w", err)
		}
	}
	w, err := wire.New(stream, wire.DeriveKey(session, "data"))
	if err != nil {
		_ = tr.Close()
		return nil, nil, err
	}
	return w, func() { _ = tr.Close() }, nil
}

// establishRelay 经中继建立传输：TCP 接入 + 令牌配对 + AEAD 消息帧。
// 首帧即完成认证(无口令者产不出合法帧)。
func establishRelay(session []byte, relayAddr, token string) (*wire.Conn, func(), error) {
	tcp, err := net.DialTimeout("tcp", relayAddr, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("中继接入: %w", err)
	}
	if _, err := tcp.Write([]byte("RELAY " + token + "\n")); err != nil {
		_ = tcp.Close()
		return nil, nil, fmt.Errorf("中继令牌发送: %w", err)
	}
	w, err := wire.New(tcp, wire.DeriveKey(session, "data"))
	if err != nil {
		_ = tcp.Close()
		return nil, nil, err
	}
	return w, func() { _ = tcp.Close() }, nil
}
