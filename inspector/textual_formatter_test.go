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
			name:      "rebar maps to the hex type",
			component: model.Component{CompName: "cowboy", CompVersion: "2.9.0", EcoRepo: model.EcoRepo{Ecosystem: "rebar"}},
			want:      "pkg:hex/cowboy@2.9.0",
		},
		{
			// Verified against the real OSV Hex database: ash 3.5.0 is the
			// version named by EEF-CVE-2025-48042 and EEF-CVE-2025-48043.
			name:      "rebar advisory version",
			component: model.Component{CompName: "ash", CompVersion: "3.5.0", EcoRepo: model.EcoRepo{Ecosystem: "rebar"}},
			want:      "pkg:hex/ash@3.5.0",
		},
		{
			name:      "cran packages use the cran type",
			component: model.Component{CompName: "readxl", CompVersion: "1.4.1", EcoRepo: model.EcoRepo{Ecosystem: "cran"}},
			want:      "pkg:cran/readxl@1.4.1",
		},
		{
			// META.json yields module names, and ':' is legal in a purl name.
			name:      "perl maps to the cpan type",
			component: model.Component{CompName: "Text::CSV", CompVersion: "2.00", EcoRepo: model.EcoRepo{Ecosystem: "perl"}},
			want:      "pkg:cpan/Text::CSV@2.00",
		},
		{
			name:      "swift keeps host and owner in the namespace",
			component: model.Component{CompName: "github.com/Alamofire/Alamofire", CompVersion: "5.4.3", EcoRepo: model.EcoRepo{Ecosystem: "spm"}},
			want:      "pkg:swift/github.com/Alamofire/Alamofire@5.4.3",
		},
		{
			name:      "swift without a path yields a bare name",
			component: model.Component{CompName: "Alamofire", CompVersion: "5.4.3", EcoRepo: model.EcoRepo{Ecosystem: "spm"}},
			want:      "pkg:swift/Alamofire@5.4.3",
		},
		{
			// ohpm (OpenHarmony) has no package-url type. Omitting the purl is
			// deliberate: inventing one would point consumers at a namespace
			// that does not exist.
			name:      "ohpm has no purl type",
			component: model.Component{CompName: "@ohos/hypium", CompVersion: "1.0.6", EcoRepo: model.EcoRepo{Ecosystem: "ohpm"}},
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

func TestComponentName(t *testing.T) {
	cases := []struct {
		component model.Component
		want      string
	}{
		{model.Component{CompName: "com.google.guava:guava", EcoRepo: model.EcoRepo{Ecosystem: "maven"}}, "guava"},
		{model.Component{CompName: "guava", EcoRepo: model.EcoRepo{Ecosystem: "maven"}}, "guava"},
		{model.Component{CompName: "lodash", EcoRepo: model.EcoRepo{Ecosystem: "npm"}}, "lodash"},
		{model.Component{CompName: "@angular/core", EcoRepo: model.EcoRepo{Ecosystem: "npm"}}, "@angular/core"},
	}
	for _, c := range cases {
		if got := componentName(c.component); got != c.want {
			t.Errorf("componentName(%+v) = %q, want %q", c.component, got, c.want)
		}
	}
}

func TestUnmappedEcosystems(t *testing.T) {
	nodes := []model.Component{
		{CompName: "guava", EcoRepo: model.EcoRepo{Ecosystem: "maven"}},
		{CompName: "lodash", EcoRepo: model.EcoRepo{Ecosystem: "npm"}},
		{CompName: "@ohos/hypium", EcoRepo: model.EcoRepo{Ecosystem: "ohpm"}},
		{CompName: "@ohos/axios", EcoRepo: model.EcoRepo{Ecosystem: "ohpm"}},
		// A component without a name is skipped: there is nothing to identify.
		{EcoRepo: model.EcoRepo{Ecosystem: "ohpm"}},
	}

	ecosystems, count := unmappedEcosystems(nodes)
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
	if len(ecosystems) != 1 || ecosystems[0] != "ohpm" {
		t.Errorf("ecosystems = %v, want [ohpm]", ecosystems)
	}

	// A fully mapped graph reports nothing, which keeps the annotation out of
	// ordinary documents.
	if ecos, n := unmappedEcosystems(nodes[:2]); n != 0 || ecos != nil {
		t.Errorf("mapped graph reported %v/%d, want nil/0", ecos, n)
	}
}
