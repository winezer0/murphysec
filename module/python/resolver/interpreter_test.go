package resolver

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestFindPythonReportsUnavailableInterpreter(t *testing.T) {
	path := t.TempDir()
	t.Setenv("PATH", path)

	_, err := FindPython(context.Background())
	if !errors.Is(err, ErrPythonUnavailable) {
		t.Fatalf("FindPython() error = %v, want ErrPythonUnavailable", err)
	}
}

func TestWithTemporaryWorkspaceCleansUpAfterFailure(t *testing.T) {
	parent := t.TempDir()
	wantErr := errors.New("resolver failed")
	var workspace string

	err := withTemporaryWorkspace(parent, func(path string) error {
		workspace = path
		if _, err := os.Stat(path); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("withTemporaryWorkspace() error = %v, want wrapped resolver error", err)
	}
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatalf("temporary workspace still exists after failure: stat error = %v", err)
	}
}

func TestSelectPipReportsUnavailableCommand(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := selectPip(context.Background()); !errors.Is(err, ErrPipUnavailable) {
		t.Fatalf("selectPip() error = %v, want ErrPipUnavailable", err)
	}
}
