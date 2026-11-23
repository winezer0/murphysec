package python

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/murphysecurity/murphysec/infra/logctx"
	"github.com/murphysecurity/murphysec/model"
	"github.com/murphysecurity/murphysec/module/python/resolver"
	"github.com/murphysecurity/murphysec/scanerr"
	"go.uber.org/zap"
)

func TestCollectDepsInfoRetainsVersionsFromNestedRequirements(t *testing.T) {
	root := t.TempDir()
	manifests := map[string]string{
		"requirements.txt":                 "aiohttp==3.14.4\n",
		"base/apis/imgen/requirements.txt": "aiohttp>=3.8.0\n",
		"base/apis/vgen/requirements.txt":  "aiohttp>=3.8.0\n",
	}
	for name, contents := range manifests {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}

	scanTask := &model.ScanTask{ProjectPath: root, IsNoBuild: true, IsInternalCmd: true}
	ctx := logctx.With(context.Background(), zap.NewNop())
	ctx = model.WithInspectionTask(ctx, scanTask.BuildInspectionTask(root))
	got, err := collectDepsInfo(ctx, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []pythonDependency{{name: "aiohttp", version: "3.14.4", declaration: "==3.14.4"}, {name: "aiohttp", version: "3.8.0", declaration: ">=3.8.0"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collected components = %#v, want %#v", got, want)
	}
	if !hasConflictingVersions(got) {
		t.Fatal("different manifest versions were not recognized as a conflict")
	}
}

func TestCollectDepsInfoDoesNotProbeHostPipInNoBuildMode(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("requests==2.32.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.py"), []byte("import flask\n"), 0600); err != nil {
		t.Fatal(err)
	}
	scanTask := &model.ScanTask{ProjectPath: root, IsNoBuild: true}
	ctx := logctx.With(context.Background(), zap.NewNop())
	ctx = model.WithInspectionTask(ctx, scanTask.BuildInspectionTask(root))
	called := false
	lookup := func(context.Context) (map[string]string, error) {
		called = true
		return map[string]string{"flask": "3.0.0"}, nil
	}

	components, err := collectDepsInfo(ctx, root, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("host pip version lookup was called in no-build mode")
	}
	if !reflect.DeepEqual(components, []pythonDependency{{name: "flask"}, {name: "requests", version: "2.32.0", declaration: "==2.32.0"}}) {
		t.Fatalf("components = %#v, want unresolved flask and declared requests", components)
	}
}

func TestInspectProjectFallsBackWhenPythonUnavailable(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("requests==2.32.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.py"), []byte("import flask\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())

	scanTask := &model.ScanTask{ProjectPath: root}
	ctx := logctx.With(context.Background(), zap.NewNop())
	ctx = scanerr.WithCtx(ctx)
	ctx = model.WithInspectionTask(ctx, scanTask.BuildInspectionTask(root))
	if err := (Inspector{}).InspectProject(ctx); err != nil {
		t.Fatalf("InspectProject() error = %v, want static fallback", err)
	}
	if len(scanTask.Modules) != 1 {
		t.Fatalf("module count = %d, want 1", len(scanTask.Modules))
	}
	versions := make(map[string]string)
	for _, dependency := range scanTask.Modules[0].Dependencies {
		versions[dependency.CompName] = dependency.CompVersion
	}
	if versions["requests"] != "2.32.0" || versions["flask"] != "" {
		t.Fatalf("static fallback dependencies = %#v, want requests 2.32.0 and unresolved flask", versions)
	}
	warnings := scanerr.GetAll(ctx)
	if len(warnings) != 1 || warnings[0].Kind != scanerr.KindPythonResolutionDegraded {
		t.Fatalf("scan warnings = %#v, want Python resolution degradation warning", warnings)
	}
}

func TestHasConflictingVersions(t *testing.T) {
	for _, test := range []struct {
		name       string
		components []pythonDependency
		want       bool
	}{
		{"same version across manifests", []pythonDependency{{name: "aiohttp", version: "3.8.0"}, {name: "aiohttp", version: "3.8.0"}}, false},
		{"different versions", []pythonDependency{{name: "aiohttp", version: "3.8.0"}, {name: "aiohttp", version: "3.14.4"}}, true},
		{"unknown alongside a version", []pythonDependency{{name: "aiohttp"}, {name: "aiohttp", version: "3.8.0"}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := hasConflictingVersions(test.components); got != test.want {
				t.Fatalf("hasConflictingVersions() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestToModelDependenciesPreservesTreeRelations(t *testing.T) {
	got := toModelDependencies([]resolver.Dependency{{
		Name: "requests", Version: "2.32.0",
		Dependencies: []resolver.Dependency{{Name: "urllib3", Version: "2.2.0"}},
	}})
	if len(got) != 1 || got[0].CompName != "requests" || got[0].CompVersion != "2.32.0" {
		t.Fatalf("direct dependencies = %#v, want requests 2.32.0", got)
	}
	if got[0].DependencyRelation != model.DependencyRelationDirect {
		t.Fatalf("direct relation = %q, want %q", got[0].DependencyRelation, model.DependencyRelationDirect)
	}
	if len(got[0].Dependencies) != 1 || got[0].Dependencies[0].DependencyRelation != model.DependencyRelationTransitive {
		t.Fatalf("transitive dependencies = %#v, want one transitive urllib3", got[0].Dependencies)
	}
}
