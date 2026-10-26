package nuget

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanPackagesConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "packages.config")
	data := `<?xml version="1.0" encoding="utf-8"?><packages><package id="Newtonsoft.Json" version="13.0.1" targetFramework="net45" /><package id="DevOnly" version="1.0.0" developmentDependency="true" /></packages>`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencies, err := inspectPkgConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(dependencies) != 1 {
		t.Fatalf("got %d dependencies, want only the runtime package", len(dependencies))
	}
	if got := dependencies[0].Component.CompName; got != "Newtonsoft.Json" {
		t.Errorf("package name = %q, want Newtonsoft.Json", got)
	}
	if got := dependencies[0].Component.CompVersion; got != "13.0.1" {
		t.Errorf("package version = %q, want 13.0.1", got)
	}
}
