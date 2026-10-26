package go_mod

import (
	"bufio"
	"io"
	"os"
	"strings"

	"golang.org/x/mod/modfile"
)

// vendorModule 是 vendor/modules.txt 里的一条模块记录。
type vendorModule struct {
	Path string
	// Version 是实际参与编译的版本：replace 已经在这里生效。
	Version string
	// Explicit 表示该模块出现在主模块 go.mod 的 require 列表里。
	//
	// 注意它不等于「业务上的直接依赖」：Go 1.17 的 go.mod 会把间接依赖也写成
	// require（带 `// indirect` 注释），所以一个 tidy 过的 vendor 工程里每个模块
	// 都是 explicit。判断直接/间接要看 go.mod 的注释，见 goModRelations。
	Explicit bool
}

// parseVendorModules 解析 vendor/modules.txt。
//
// 为什么优先用它而不是 go.mod：vendor 模式下 go 命令已经把 replace、MVS 和
// exclude 全部算完，modules.txt 就是这次构建真正用的模块集合；go.mod 只是
// 输入。两者在 replace 过的项目上会给出不同版本，见 go.go 的调用处。
//
// 文件格式（cmd/go/internal/modload/vendor.go 写出）：
//
//	# github.com/foo/bar v1.2.3            <- 一条模块
//	## explicit                            <- 主模块直接依赖
//	github.com/foo/bar                     <- 该模块提供的包，忽略
//	# github.com/a/b v1.0.0 => github.com/fork/b v1.2.0
//	# github.com/old/m v1.0.0 => ./local   <- 本地目录替换，版本不变
//	...
//	# github.com/a/b => github.com/fork/b v1.2.0   <- 末尾的 replace 汇总，跳过
//
// 最后这种不带版本的行只是复述 replace 指令，把它当模块会凭空多出一条组件。
func parseVendorModules(r io.Reader) ([]vendorModule, error) {
	var out []vendorModule
	var curIdx = -1
	var sc = bufio.NewScanner(r)
	// 单行最长见过 200 字节左右，留足余量避免长路径触发 bufio 上限。
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var line = strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "## "):
			// "## explicit" 或 "## explicit; go 1.17"
			if curIdx >= 0 && strings.Contains(line, "explicit") {
				out[curIdx].Explicit = true
			}
		case strings.HasPrefix(line, "# "):
			curIdx = -1
			var body = strings.TrimSpace(strings.TrimPrefix(line, "# "))
			var left, right string
			if i := strings.Index(body, "=>"); i >= 0 {
				left = strings.TrimSpace(body[:i])
				right = strings.TrimSpace(body[i+2:])
			} else {
				left = body
			}
			var lp = strings.Fields(left)
			if len(lp) < 2 {
				// 不带版本的 `# A => B v2`：replace 汇总行，不是模块。
				continue
			}
			var m = vendorModule{Path: lp[0], Version: lp[1]}
			if right != "" {
				var rp = strings.Fields(right)
				switch {
				case len(rp) >= 2 && !isLocalReplacePath(rp[0]):
					// 换成另一个模块或另一个版本：报实际参与编译的那个。
					m.Path, m.Version = rp[0], rp[1]
				case len(rp) == 1:
					// `=> ./local`：源码换成本地目录，模块身份不变。
				}
			}
			out = append(out, m)
			curIdx = len(out) - 1
		}
	}
	if e := sc.Err(); e != nil {
		return nil, e
	}
	return out, nil
}

// readVendorModules 读取 <dir>/vendor/modules.txt。
//
// 文件不存在时 ok 为 false，调用方应退回解析 go.mod；存在但读不动时报错也不
// 致命（vendor 目录可能不完整），同样退回 go.mod。
func readVendorModules(path string) (mods []vendorModule, ok bool) {
	var f, e = os.Open(path)
	if e != nil {
		return nil, false
	}
	defer f.Close()
	mods, e = parseVendorModules(f)
	if e != nil || len(mods) == 0 {
		return nil, false
	}
	return mods, true
}

// goModRelations 从 go.mod 读出「哪些模块被主模块直接 import」。
//
// 返回值以 replace 生效后的模块路径为 key，值表示是否直接依赖，与
// vendor/modules.txt 里的路径对齐。
//
// 之所以不能直接用 modules.txt 的 `## explicit`：Go 1.17 的 go.mod 会把间接
// 依赖也写成 require 并在行尾标 `// indirect`，于是 vendor 里每个模块都是
// explicit。注释才是「业务上直接」的唯一来源。
func goModRelations(path string) map[string]bool {
	var data, e = os.ReadFile(path)
	if e != nil {
		return nil
	}
	var f, err = modfile.Parse(path, data, nil)
	if err != nil {
		return nil
	}
	var tbl = newReplaceTable(f)
	var out = make(map[string]bool, len(f.Require))
	for _, req := range f.Require {
		var name, _, _ = tbl.apply(req.Mod.Path, req.Mod.Version)
		out[name] = !req.Indirect
	}
	return out
}
