package go_mod

import (
	"strings"
	"testing"
)

// 取自 inott-epg-go 的真实片段，含 replace、本地目录替换和末尾的汇总行。
const sampleVendorModules = `# github.com/Jeffail/gabs v1.4.0
## explicit
github.com/Jeffail/gabs
# github.com/go-redis/redis v6.15.9+incompatible
github.com/go-redis/redis
github.com/go-redis/redis/internal
# github.com/unrolled/render v1.5.0 => github.com/unrolled/render v0.0.0-20160218130117-198ad4d8b8a4
## explicit; go 1.17
github.com/unrolled/render
# github.com/old/local v1.2.0 => ./forks/local
github.com/old/local
# github.com/unrolled/render => github.com/unrolled/render v0.0.0-20160218130117-198ad4d8b8a4
`

func TestParseVendorModules(t *testing.T) {
	var mods, err = parseVendorModules(strings.NewReader(sampleVendorModules))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var want = []vendorModule{
		{Path: "github.com/Jeffail/gabs", Version: "v1.4.0", Explicit: true},
		{Path: "github.com/go-redis/redis", Version: "v6.15.9+incompatible"},
		// replace 到同一模块的另一个版本：报实际编译的那个版本。
		{Path: "github.com/unrolled/render", Version: "v0.0.0-20160218130117-198ad4d8b8a4", Explicit: true},
		// replace 到本地目录：模块身份与版本都不变。
		{Path: "github.com/old/local", Version: "v1.2.0"},
	}
	if len(mods) != len(want) {
		t.Fatalf("got %d modules, want %d: %+v", len(mods), len(want), mods)
	}
	for i := range want {
		if mods[i] != want[i] {
			t.Fatalf("module[%d] = %+v, want %+v", i, mods[i], want[i])
		}
	}
}

func TestParseVendorModulesSkipsReplaceSummary(t *testing.T) {
	// 只有 replace 汇总行、没有模块行时，不能凭空造出组件。
	var mods, err = parseVendorModules(strings.NewReader(
		"# github.com/a/b => github.com/fork/b v1.2.0\n# github.com/c/d => ./local\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(mods) != 0 {
		t.Fatalf("replace summary lines must be skipped, got %+v", mods)
	}
}

func TestParseVendorModulesEmpty(t *testing.T) {
	var mods, err = parseVendorModules(strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(mods) != 0 {
		t.Fatalf("empty input must yield no modules, got %+v", mods)
	}
}
