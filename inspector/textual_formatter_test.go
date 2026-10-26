package inspector

import (
	"testing"

	"github.com/murphysecurity/murphysec/model"
)

func TestComponentPURL(t *testing.T) {
	cases := []struct {
		name      string
		component model.Component
		want      string
	}{
		{
			name:      "maven splits group and artifact",
			component: model.Component{CompName: "com.google.guava:guava", CompVersion: "30.0-jre", EcoRepo: model.EcoRepo{Ecosystem: "maven"}},
			want:      "pkg:maven/com.google.guava/guava@30.0-jre",
		},
		{
			name:      "maven without a group keeps a bare name",
			component: model.Component{CompName: "guava", CompVersion: "30.0-jre", EcoRepo: model.EcoRepo{Ecosystem: "maven"}},
			want:      "pkg:maven/guava@30.0-jre",
		},
		{
			name:      "npm scoped package encodes the scope separator",
			component: model.Component{CompName: "@angular/core", CompVersion: "12.3.1", EcoRepo: model.EcoRepo{Ecosystem: "npm"}},
			want:      "pkg:npm/%40angular/core@12.3.1",
		},
		{
			name:      "npm plain package",
			component: model.Component{CompName: "lodash", CompVersion: "4.17.21", EcoRepo: model.EcoRepo{Ecosystem: "npm"}},
			want:      "pkg:npm/lodash@4.17.21",
		},
		{
			name:      "go keeps the module path",
			component: model.Component{CompName: "github.com/gorilla/mux", CompVersion: "v1.7.4", EcoRepo: model.EcoRepo{Ecosystem: "go"}},
			want:      "pkg:golang/github.com/gorilla/mux@v1.7.4",
		},
		{
			name:      "pypi uses the pypi type",
			component: model.Component{CompName: "requests", CompVersion: "2.19.1", EcoRepo: model.EcoRepo{Ecosystem: "pypi"}},
			want:      "pkg:pypi/requests@2.19.1",
		},
		{
			name:      "bundler maps to the gem type",
			component: model.Component{CompName: "rails", CompVersion: "6.0.0", EcoRepo: model.EcoRepo{Ecosystem: "bundler"}},
			want:      "pkg:gem/rails@6.0.0",
		},
		{
			name:      "pubspec maps to the pub type",
			component: model.Component{CompName: "http", CompVersion: "0.13.0", EcoRepo: model.EcoRepo{Ecosystem: "pubspec"}},
			want:      "pkg:pub/http@0.13.0",
		},
		{
			name:      "ecosystem without a purl type yields nothing",
			component: model.Component{CompName: "foo", CompVersion: "1.0", EcoRepo: model.EcoRepo{Ecosystem: "perl"}},
			want:      "",
		},
		{
			name:      "unknown ecosystem yields nothing",
			component: model.Component{CompName: "foo", CompVersion: "1.0", EcoRepo: model.EcoRepo{Ecosystem: "somethingelse"}},
			want:      "",
		},
		{
			name:      "empty name yields nothing",
			component: model.Component{CompName: "", CompVersion: "1.0", EcoRepo: model.EcoRepo{Ecosystem: "maven"}},
			want:      "",
		},
		{
			name:      "missing version omits the @ suffix",
			component: model.Component{CompName: "lodash", CompVersion: "", EcoRepo: model.EcoRepo{Ecosystem: "npm"}},
			want:      "pkg:npm/lodash",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := componentPURL(c.component); got != c.want {
				t.Errorf("componentPURL(%+v) = %q, want %q", c.component, got, c.want)
			}
		})
	}
}
