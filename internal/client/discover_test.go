package client

import (
	"os"
	"testing"
)

// HRW 排序:同表同口令确定性同序;口令变化则大概率换序(分片生效)。
func TestHRWOrder(t *testing.T) {
	bases := []string{"http://a:12346", "http://b:12346", "http://c:12346", "http://d:12346"}

	orig := append([]string{}, bases...)
	hrwOrder(bases, "ABCD-EFGH-JKMN")
	first := append([]string{}, bases...)
	hrwOrder(bases, "ABCD-EFGH-JKMN")
	if strings2Join(bases) != strings2Join(first) {
		t.Fatal("同口令两次排序结果不一致(确定性破坏)")
	}
	hrwOrder(bases, "PQRS-TUVX-WZ23")
	second := append([]string{}, bases...)
	if strings2Join(first) == strings2Join(second) {
		t.Log("提示:不同口令同序(理论可能,多次采样不应恒同)")
	}
	_ = orig
	t.Logf("code1 → %v; code2 → %v", first, second)
	// 完整性:排序不丢元素
	seen := map[string]bool{}
	for _, b := range append(first, second...) {
		seen[b] = true
	}
	if len(seen) != 4 {
		t.Fatalf("排序丢失元素: %v", seen)
	}
}

// registryChain:env 多源并入+去重+规范化(IP/带 scheme 直通;域名在 CI 无解析剔除)。
func TestRegistryChain(t *testing.T) {
	t.Setenv("PB_P2P_REGISTRIES", " http://b:12346 , 10.0.0.5:12346,http://b:12346")
	c, err := New(Options{Registry: "http://a:12346", NodeKeyPath: t.TempDir() + "/k", Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	chain := c.registryChain("ABCD-EFGH-JKMN")
	set := map[string]bool{}
	for _, b := range chain {
		set[b] = true
	}
	for _, want := range []string{"http://a:12346", "http://b:12346", "http://10.0.0.5:12346"} {
		if !set[want] {
			t.Fatalf("链缺少 %s: %v", want, chain)
		}
	}
	if len(chain) != 3 {
		t.Fatalf("重复去重失败: %v", chain)
	}
	_ = os.Unsetenv("PB_P2P_REGISTRIES")
}

func strings2Join(xs []string) string {
	out := ""
	for _, x := range xs {
		out += x + "|"
	}
	return out
}
