package npm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/murphysecurity/murphysec/model"
)

func TestScanNpmProjectWithoutPackageJSON(t *testing.T) {
	tests := []struct {
		name string
		lock string
	}{
		{
			name: "v1",
			lock: `{"name":"demo","version":"1.0.0","lockfileVersion":1,"dependencies":{"left-pad":{"version":"1.3.0"}}}`,
		},
		{
			name: "v2",
			lock: `{"name":"demo","version":"1.0.0","lockfileVersion":2,"packages":{"":{"name":"demo","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0"}},"dependencies":{"left-pad":{"version":"1.3.0"}}}`,
		},
		{
			name: "v3",
			lock: `{"name":"demo","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"demo","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, LockFileName), []byte(tt.lock), 0600); err != nil {
				t.Fatal(err)
			}

			scanTask := &model.ScanTask{ProjectPath: dir}
			ctx := model.WithInspectionTask(context.Background(), scanTask.BuildInspectionTask(dir))
			ctx = context.WithValue(ctx, model.BasePathKey, filepath.Join(filepath.Dir(dir), "base"))
			modules, err := ScanNpmProject(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(modules) != 1 {
				t.Fatalf("got %d modules, want 1", len(modules))
			}
			module := modules[0]
			if module.ModuleName != "demo" || module.ModuleVersion != "1.0.0" {
				t.Fatalf("unexpected module metadata: %q@%q", module.ModuleName, module.ModuleVersion)
			}
			if len(module.Dependencies) != 1 || module.Dependencies[0].CompName != "left-pad" || module.Dependencies[0].CompVersion != "1.3.0" {
				t.Fatalf("unexpected dependencies: %#v", module.Dependencies)
			}
		})
	}
}
