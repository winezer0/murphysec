package scanerr

import (
	"context"
	list "github.com/bahlo/generic-list-go"
)

type Param struct {
	Kind    string `json:"kind"`
	Content string `json:"content"`
}

type ctxKeyType string

var key = ctxKeyType("scanErrorCtxKey")

func WithCtx(ctx context.Context) context.Context {
	return context.WithValue(ctx, key, list.New[Param]())
}

func Add(ctx context.Context, e Param) {
	if l, ok := ctx.Value(key).(*list.List[Param]); ok {
		l.PushBack(e)
	}
}

func GetAll(ctx context.Context) []Param {
	l, ok := ctx.Value(key).(*list.List[Param])
	if !ok {
		return make([]Param, 0)
	}
	var rs = make([]Param, 0, l.Len())
	var f = l.Front()
	for f != nil {
		rs = append(rs, f.Value)
		f = f.Next()
	}
	return rs
}

const KindMavenNotFound = "mvn_not_found"
const KindMavenFailed = "mvn_failed"
const KindBuildDisabled = "build_disabled"
const KindMavenTimeout = "mvn_timeout_killed"
const KindConanNotFound = "conan_not_found"
const KindConanFailed = "conan_failed"
const KindDotnetNotFound = "dotnet_not_found"
const KindNugetFailed = "nuget_failed"
const KindInspectorFailed = "inspector_failed"

// KindGoModExcludeHit 表示一条 require 的版本同时被 go.mod 的 exclude 排除。
//
// 这种 go.mod 通常没有 tidy 过。静态解析不重算 MVS，无法给出应当替代的版本，
// 只能把组件按原样保留并告警：删掉组件会让它的漏洞一起消失。
const KindGoModExcludeHit = "go_mod_exclude_hit"
