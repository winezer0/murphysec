package go_mod

import (
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

// moduleReplacement 是一条 replace 指令右侧展开后的结果。
//
// version 为空只有一种合法情况：右侧是本地目录（replace A => ./local），
// 此时 go.mod 不允许再写版本号。
type moduleReplacement struct {
	path    string
	version string
}

// replaceTable 把 go.mod 的 replace 指令索引成两张表。
//
// go.mod 允许两种写法，语义不同：
//
//	replace A => B v1.2.3         A 的所有版本都替换成 B v1.2.3
//	replace A v1.0.0 => B v1.2.4  只替换 A@v1.0.0
//
// 精确匹配必须优先于通配匹配：同一份 go.mod 里两条都写时，Go 用精确的那条。
type replaceTable struct {
	exact map[string]moduleReplacement // key: path@version
	all   map[string]moduleReplacement // key: path
}

func newReplaceTable(f *modfile.File) *replaceTable {
	var t = &replaceTable{
		exact: make(map[string]moduleReplacement),
		all:   make(map[string]moduleReplacement),
	}
	if f == nil {
		return t
	}
	for _, r := range f.Replace {
		if r == nil || r.Old.Path == "" {
			continue
		}
		var rep = moduleReplacement{path: r.New.Path, version: r.New.Version}
		if r.Old.Version == "" {
			t.all[r.Old.Path] = rep
		} else {
			t.exact[r.Old.Path+"@"+r.Old.Version] = rep
		}
	}
	return t
}

// apply 返回 replace 生效后的模块路径与版本。
//
// replaced 为 false 时返回值与入参相同，调用方不必区分「没命中」和「命中了
// 本地目录替换」——两者的结论都是按 require 里的原值上报。
func (t *replaceTable) apply(path, version string) (newPath, newVersion string, replaced bool) {
	if t == nil {
		return path, version, false
	}
	var rep moduleReplacement
	var ok bool
	if rep, ok = t.exact[path+"@"+version]; !ok {
		rep, ok = t.all[path]
	}
	if !ok {
		return path, version, false
	}
	// `replace A => ./local`：源码换成本地目录，但 go list -m 仍然把这一项报成
	// A@<require 里的版本>，只额外给一个 Replace.Dir 字段。版本号不能凭空清空，
	// 否则 SBOM 里会多出一个无版本组件，OSV 无从匹配，反而制造漏报。
	if isLocalReplacePath(rep.path) {
		return path, version, false
	}
	// 右侧不带版本的合法写法只有本地目录一种。modfile.Parse 在宽松模式下会接受
	// 其它情况，这里按「没有替换」处理，避免把非法 go.mod 的影响放大。
	if rep.version == "" {
		return path, version, false
	}
	return rep.path, rep.version, true
}

// isLocalReplacePath 判断 replace 右侧是不是本地文件系统路径。
//
// go.mod 里统一用正斜杠，但 Windows 上手写的 go.mod 偶尔出现反斜杠，一并识别。
func isLocalReplacePath(p string) bool {
	if p == "" {
		return false
	}
	for _, prefix := range []string{"./", "../", ".\\", "..\\"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return filepath.IsAbs(p)
}

// excludedVersions 收集 go.mod 的 exclude 指令，key 为 path@version。
//
// exclude 只表达「这个版本不要用」。静态解析不会重算 MVS，无法替用户挑一个
// 更高的版本，所以命中时保留原条目、单独记一条告警，比静默删掉安全：删掉会
// 直接把一个组件从 SBOM 里抹去，漏洞也就跟着消失。
func excludedVersions(f *modfile.File) map[string]struct{} {
	var s = make(map[string]struct{})
	if f == nil {
		return s
	}
	for _, e := range f.Exclude {
		if e == nil || e.Mod.Path == "" {
			continue
		}
		s[e.Mod.Path+"@"+e.Mod.Version] = struct{}{}
	}
	return s
}
