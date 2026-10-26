package npm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/murphysecurity/murphysec/model"
)

func TestSkipWorkspaceDirectoryKeepsMonorepoRoot(t *testing.T) {
	root := t.TempDir()
	member := filepath.Join(root, "packages", "app")
	if err := os.MkdirAll(member, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"workspaces":["packages/*"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(member, "package.json"), []byte(`{"name":"app"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), model.BasePathKey, root)
	if !skipWorkspaceDirectory(ctx, root) {
		t.Fatal("monorepo root was classified as its own workspace member")
	}
	if skipWorkspaceDirectory(ctx, member) {
		t.Fatal("workspace member was not recognized")
	}
}
