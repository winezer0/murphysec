package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/murphysecurity/murphysec/model"
)

func scanLockFixture(t *testing.T, data []byte, paired bool) ([]model.Module, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, LockFileName), data, 0600); err != nil {
		t.Fatal(err)
	}
	if paired {
		var lock struct{ Packages map[string]json.RawMessage }
		_ = json.Unmarshal(data, &lock)
		manifest := lock.Packages[""]
		if len(manifest) == 0 {
			manifest = []byte("{\"name\":\"demo\"}")
		}
		if err := os.WriteFile(filepath.Join(dir, PackageFileName), manifest, 0600); err != nil {
			t.Fatal(err)
		}
	}
	task := &model.ScanTask{ProjectPath: dir}
	ctx := model.WithInspectionTask(context.Background(), task.BuildInspectionTask(dir))
	ctx = context.WithValue(ctx, model.BasePathKey, filepath.Join(filepath.Dir(dir), "base"))
	if !(Inspector{}).CheckDir(ctx, dir) {
		t.Fatal("npm project was not discovered")
	}
	return ScanNpmProject(ctx)
}

func TestLockfileNestedResolution(t *testing.T) {
	data, err := os.ReadFile("testdata/lockfile-nested.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{2, 3} {
		for _, paired := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d/paired=%v", version, paired), func(t *testing.T) {
				contents := []byte(strings.Replace(string(data), "\"lockfileVersion\": 3", fmt.Sprintf("\"lockfileVersion\": %d", version), 1))
				modules, err := scanLockFixture(t, contents, paired)
				if err != nil || len(modules) != 1 {
					t.Fatalf("modules=%v err=%v", modules, err)
				}
				child := func(items []model.DependencyItem, name string) model.DependencyItem {
					for _, n := range items {
						if n.CompName == name {
							return n
						}
					}
					t.Fatalf("missing %s", name)
					return model.DependencyItem{}
				}
				a := child(child(modules[0].Dependencies, "wrapper-a").Dependencies, "common")
				b := child(child(modules[0].Dependencies, "wrapper-b").Dependencies, "common")
				if child(a.Dependencies, "lodash").CompVersion != "4.17.20" || child(b.Dependencies, "lodash").CompVersion != "4.17.21" {
					t.Fatal("nested dependency versions lost")
				}
				var walk func([]model.DependencyItem)
				walk = func(items []model.DependencyItem) {
					for _, n := range items {
						if n.CompName == "shared" && (!n.IsOnline.Valid || !n.IsOnline.Value) {
							t.Error("runtime dependency classified as development-only")
						}
						if n.CompName == "dev-tool" && n.IsOnline.Value {
							t.Error("development classification lost")
						}
						walk(n.Dependencies)
					}
				}
				walk(modules[0].Dependencies)
			})
		}
	}
}

func TestLockfileWorkspaceWithoutManifests(t *testing.T) {
	data, err := os.ReadFile("testdata/lockfile-workspace.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{2, 3} {
		contents := []byte(strings.Replace(string(data), "\"lockfileVersion\": 3", fmt.Sprintf("\"lockfileVersion\": %d", version), 1))
		modules, err := scanLockFixture(t, contents, false)
		if err != nil || len(modules) != 1 {
			t.Fatalf("v%d modules=%v err=%v", version, modules, err)
		}
		found := false
		for _, n := range modules[0].Dependencies {
			found = found || n.CompName == "lodash" && n.CompVersion == "4.17.21"
		}
		if !found {
			t.Fatalf("v%d workspace dependency missing", version)
		}
	}
}

func TestInvalidLockfileErrors(t *testing.T) {
	cases := []struct{ name, data string }{
		{"null-legacy-dependencies", "{\"name\":\"demo\",\"lockfileVersion\":1,\"dependencies\":null}"},
		{"invalid-json", "{"},
		{"null-document", "null"},
		{"missing-version", "{\"packages\":{\"\":{}}}"},
		{"unknown-version", "{\"lockfileVersion\":4,\"packages\":{\"\":{}}}"},
		{"wrong-version-type", "{\"lockfileVersion\":\"3\",\"packages\":{\"\":{}}}"},
		{"missing-root-v2", "{\"lockfileVersion\":2,\"packages\":{\"node_modules/lodash\":{\"version\":\"4.17.21\"}}}"},
		{"missing-root-v3", "{\"lockfileVersion\":3,\"packages\":{\"node_modules/lodash\":{\"version\":\"4.17.21\"}}}"},
		{"null-root", "{\"lockfileVersion\":3,\"packages\":{\"\":null}}"},
		{"null-package", "{\"lockfileVersion\":3,\"packages\":{\"\":{},\"node_modules/lodash\":null}}"},
		{"null-legacy-package", "{\"lockfileVersion\":1,\"dependencies\":{\"lodash\":null}}"},
		{"missing-package-version", "{\"lockfileVersion\":3,\"packages\":{\"\":{},\"node_modules/lodash\":{}}}"},
		{"missing-required-dependency", "{\"lockfileVersion\":3,\"packages\":{\"\":{\"dependencies\":{\"lodash\":\"4.17.21\"}}}}"},
		{"broken-link", "{\"lockfileVersion\":3,\"packages\":{\"\":{},\"node_modules/app\":{\"link\":true,\"resolved\":\"packages/missing\"}}}"},
	}
	for _, tc := range cases {
		for _, paired := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/paired=%v", tc.name, paired), func(t *testing.T) {
				if _, err := scanLockFixture(t, []byte(tc.data), paired); err == nil {
					t.Fatal("invalid lockfile accepted")
				}
			})
		}
	}
}

func TestEmptyLockfile(t *testing.T) {
	for _, data := range []string{
		"{\"name\":\"empty\",\"lockfileVersion\":1}",
		"{\"lockfileVersion\":2,\"packages\":{\"\":{}}}",
		"{\"lockfileVersion\":3,\"packages\":{\"\":{}}}",
	} {
		modules, err := scanLockFixture(t, []byte(data), false)
		if err != nil || len(modules) != 1 || len(modules[0].Dependencies) != 0 {
			t.Fatalf("empty project rejected: %v %v", modules, err)
		}
	}
}
