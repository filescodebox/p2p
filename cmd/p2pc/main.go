// p2pc — FilesCodeBox P2P 设备直传参考客户端（M3）。
//
//	p2pc send 文件 --registry http://r:12346   → 输出口令,等待对端取走
//	p2pc recv <口令> --registry http://r:12346 → 接收到当前目录
//
// 流程: 注册节点+公告/解析 → WS 信令配对(身份钉定) → PAKE → 加密候选交换
// → UDP 同时开洞(失败走中继) → AEAD 消息传输(断点续传+sha256 校验)。
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/filescodebox/kit/version"
	"github.com/filescodebox/p2p/internal/client"
)

// flagSet 薄包装:统一错误输出行为。
type flagSet struct {
	*flag.FlagSet
}

func newFlagSet(name string) *flagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return &flagSet{FlagSet: fs}
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	switch cmd {
	case "send":
		send(os.Args[2:])
	case "recv":
		receive(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	case "-v", "--version", "version":
		fmt.Printf("p2pc %s (commit %s, built %s)\n", version.Version, version.BuildCommit, version.BuildTime)
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", cmd)
		usage()
	}
}

func usage() {
	fmt.Print(`p2pc — FilesCodeBox P2P 设备直传客户端

用法:
  p2pc send <文件> [--registry URL] [--code 口令] [--relay HOST:PORT]
                  [--key PATH] [--no-punch] [--quiet]
  p2pc recv <口令> [--registry URL] [--out DIR]     [--relay HOST:PORT]
                  [--key PATH] [--no-punch] [--quiet]

说明:
  --registry   p2pd 注册中心基址(默认 http://127.0.0.1:12346)
  口令格式     XXXX-XXXX-XXXX(send 自动生成;recv 原样输入,含连字符)
  传输优先 UDP 打洞直连,失败自动回落中继(中继需服务端 relay.enabled=true)
`)
	os.Exit(2)
}

func commonFlags(fs *flagSet) *client.Options {
	opt := &client.Options{Registry: "http://127.0.0.1:12346"}
	fs.StringVar(&opt.Registry, "registry", opt.Registry, "p2pd 基址")
	fs.StringVar(&opt.RelayAddr, "relay", "", "中继地址(缺省 registry host:12347)")
	fs.StringVar(&opt.NodeKeyPath, "key", client.DefaultNodeKeyPath(), "节点身份密钥路径")
	fs.BoolVar(&opt.DisablePunch, "no-punch", false, "跳过打洞直接走中继")
	fs.BoolVar(&opt.Quiet, "quiet", false, "静默模式")
	return opt
}

func send(args []string) {
	fs := newFlagSet("p2pc send")
	opt := commonFlags(fs)
	var code string
	fs.StringVar(&code, "code", "", "指定口令(缺省自动生成)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "✗ 缺少文件参数")
		os.Exit(2)
	}
	path := fs.Arg(0)
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		fmt.Fprintf(os.Stderr, "✗ 文件不可用: %s\n", path)
		os.Exit(1)
	}

	c, err := client.New(*opt)
	if err != nil {
		fail(err)
	}
	used, err := c.Send(path, strings.ToUpper(code))
	if err != nil {
		fail(err)
	}
	fmt.Printf("\n✓ 发送完成\n口令: %s\n", used)
}

func receive(args []string) {
	fs := newFlagSet("p2pc recv")
	opt := commonFlags(fs)
	out, _ := os.Getwd()
	fs.StringVar(&out, "out", out, "接收目录")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "✗ 缺少口令参数")
		os.Exit(2)
	}
	code := strings.ToUpper(strings.TrimSpace(fs.Arg(0)))

	c, err := client.New(*opt)
	if err != nil {
		fail(err)
	}
	outPath, err := c.Receive(code, out)
	if err != nil {
		fail(err)
	}
	abs, _ := filepath.Abs(outPath)
	fmt.Printf("\n✓ 接收完成: %s\n", abs)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "✗ %v\n", err)
	os.Exit(1)
}
