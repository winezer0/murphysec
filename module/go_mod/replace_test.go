package go_mod

import (
	"testing"

	"golang.org/x/mod/modfile"
)

func mustParseMod(t *testing.T, src string) *modfile.File {
	t.Helper()
	f, err := modfile.Parse("go.mod", []byte(src), nil)
	if err != nil {
		t.Fatalf("parse go.mod: %v", err)
	}
	return f
}

func TestReplaceTableApply(t *testing.T) {
	var cases = []struct {
		name         string
		mod          string
		path         string
		version      string
		wantPath     string
		wantVersion  string
		wantReplaced bool
	}{
		{
			// 本工程的真实形态：require 写 v0.6.0，replace 到旧版本。
			name:         "wildcard replace changes version",
			mod:          "module x\n\ngo 1.17\n\nrequire golang.org/x/sys v0.6.0\n\nreplace golang.org/x/sys => golang.org/x/sys v0.0.0-20210112080510-489259a85091\n",
			path:         "golang.org/x/sys",
			version:      "v0.6.0",
			wantPath:     "golang.org/x/sys",
			wantVersion:  "v0.0.0-20210112080510-489259a85091",
			wantReplaced: true,
		},
		{
			name:         "wildcard replace changes path",
			mod:          "module x\n\ngo 1.17\n\nreplace github.com/a/b => github.com/fork/b v1.2.3\n",
			path:         "github.com/a/b",
			version:      "v1.0.0",
			wantPath:     "github.com/fork/b",
			wantVersion:  "v1.2.3",
			wantReplaced: true,
		},
		{
			name:         "exact version replace only matches that version",
			mod:          "module x\n\ngo 1.17\n\nreplace github.com/a/b v1.0.0 => github.com/a/b v1.0.1\n",
			path:         "github.com/a/b",
			version:      "v1.0.0",
			wantPath:     "github.com/a/b",
			wantVersion:  "v1.0.1",
			wantReplaced: true,
		},
		{
			name:         "exact version replace leaves other versions alone",
			mod:          "module x\n\ngo 1.17\n\nreplace github.com/a/b v1.0.0 => github.com/a/b v1.0.1\n",
			path:         "github.com/a/b",
			version:      "v2.0.0",
			wantPath:     "github.com/a/b",
			wantVersion:  "v2.0.0",
			wantReplaced: false,
		},
		{
			// 两条都写时，Go 用精确的那条。
			name:         "exact wins over wildcard",
			mod:          "module x\n\ngo 1.17\n\nreplace github.com/a/b => github.com/fork/b v9.9.9\n\nreplace github.com/a/b v1.0.0 => github.com/a/b v1.0.1\n",
			path:         "github.com/a/b",
			version:      "v1.0.0",
			wantPath:     "github.com/a/b",
			wantVersion:  "v1.0.1",
			wantReplaced: true,
		},
		{
			// 本地目录替换不改变组件身份：go list -m 仍报 A@<require 版本>。
			name:         "local directory replace keeps module identity",
			mod:          "module x\n\ngo 1.17\n\nrequire github.com/a/b v1.0.0\n\nreplace github.com/a/b => ../b-local\n",
			path:         "github.com/a/b",
			version:      "v1.0.0",
			wantPath:     "github.com/a/b",
			wantVersion:  "v1.0.0",
			wantReplaced: false,
		},
		{
			name:         "dot local directory replace keeps module identity",
			mod:          "module x\n\ngo 1.17\n\nreplace github.com/a/b => ./vendor-fork/b\n",
			path:         "github.com/a/b",
			version:      "v1.0.0",
			wantPath:     "github.com/a/b",
			wantVersion:  "v1.0.0",
			wantReplaced: false,
		},
		{
			name:         "no replace",
			mod:          "module x\n\ngo 1.17\n\nrequire github.com/a/b v1.0.0\n",
			path:         "github.com/a/b",
			version:      "v1.0.0",
			wantPath:     "github.com/a/b",
			wantVersion:  "v1.0.0",
			wantReplaced: false,
		},
		{
			// replace 只对写下的路径生效，不能误伤同名子路径。
			name:         "replace does not apply to a different module",
			mod:          "module x\n\ngo 1.17\n\nreplace github.com/a/b => github.com/fork/b v1.2.3\n",
			path:         "github.com/a/bc",
			version:      "v1.0.0",
			wantPath:     "github.com/a/bc",
			wantVersion:  "v1.0.0",
			wantReplaced: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var tbl = newReplaceTable(mustParseMod(t, c.mod))
			var gotPath, gotVersion, gotReplaced = tbl.apply(c.path, c.version)
			if gotPath != c.wantPath || gotVersion != c.wantVersion || gotReplaced != c.wantReplaced {
				t.Fatalf("apply(%q, %q) = (%q, %q, %v), want (%q, %q, %v)",
					c.path, c.version, gotPath, gotVersion, gotReplaced,
					c.wantPath, c.wantVersion, c.wantReplaced)
			}
		})
	}
}

func TestReplaceTableNilSafe(t *testing.T) {
	var tbl *replaceTable
	var p, v, replaced = tbl.apply("github.com/a/b", "v1.0.0")
	if p != "github.com/a/b" || v != "v1.0.0" || replaced {
		t.Fatalf("nil table must be a no-op, got (%q, %q, %v)", p, v, replaced)
	}
}

func TestExcludedVersions(t *testing.T) {
	var f = mustParseMod(t, "module x\n\ngo 1.17\n\nexclude github.com/a/b v1.0.0\n\nexclude (\n\tgithub.com/c/d v1.5.0\n)\n")
	var got = excludedVersions(f)
	for _, want := range []string{"github.com/a/b@v1.0.0", "github.com/c/d@v1.5.0"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("excludedVersions missing %q, got %v", want, got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("excludedVersions = %v, want 2 entries", got)
	}
}
