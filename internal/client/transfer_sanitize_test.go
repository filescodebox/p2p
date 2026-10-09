package client

import "testing"

// 路径消毒守卫:目录传输不给路径穿越留门。
func TestSanitizeRel(t *testing.T) {
	ok := map[string]string{
		"a.txt":              "a.txt",
		"dir/b/c.txt":        "dir/b/c.txt",
		"目录/中文 文件.txt":       "目录/中文 文件.txt",
		"dir/./b.txt":        "dir/b.txt",
		"dir/../sibling.txt": "sibling.txt", // Clean 抵达根内,合法
	}
	for in, want := range ok {
		got, err := sanitizeRel(in)
		if err != nil || got != want {
			t.Errorf("sanitizeRel(%q)=%q,%v 期望 %q", in, got, err, want)
		}
	}
	bad := []string{
		"/etc/passwd",
		"../escape.txt",
		"..\\windows.txt",
		"C:\\Windows\\evil",
		"C:/evil",
		"",
		"   ",
		"./",
	}
	for _, in := range bad {
		if got, err := sanitizeRel(in); err == nil {
			t.Errorf("sanitizeRel(%q)=%q 应拒绝", in, got)
		}
	}
}
