package signaling

import (
	"encoding/json"
	"testing"
)

// FuzzClientFrame 任意 JSON 喂客户端帧解析不得 panic
// (payload 为 base64 []byte,是注册中心直接解析的对端输入)。
func FuzzClientFrame(f *testing.F) {
	f.Add([]byte(`{"type":"data","payload":"aGk="}`))
	f.Add([]byte(`{"type":"hello","node_id":"x","ts":1,"sig":"y"}`))
	f.Add([]byte(`{"type":`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"type":"data","payload":"!非法base64!"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var cf clientFrame
		if err := json.Unmarshal(data, &cf); err == nil {
			// 解析成功后仅做与 readPump 同款的长度判定路径
			_ = len(cf.Payload) > 1<<20
		}
		var hf helloFrame
		_ = json.Unmarshal(data, &hf)
	})
}
