package scan

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestOSVScannerSBOMCompatibility exercises the real MurphySec CLI and
// osv-scanner against common project manifests. Set OSV_SCANNER to
// the scanner executable to run this opt-in integration test.
func TestOSVScannerSBOMCompatibility(t *testing.T) {
	scanner, ok := os.LookupEnv("OSV_SCANNER")
	if !ok || scanner == "" {
		t.Skip("set OSV_SCANNER to run osv-scanner integration tests")
	}
	if _, err := os.Stat(scanner); err != nil {
		t.Fatalf("osv-scanner executable: %v", err)
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate repository root")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", ".."))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := filepath.Join(t.TempDir(), "murphysec")
	if runtime.GOOS == "windows" {
		cli += ".exe"
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", cli, ".")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build MurphySec: %v\n%s", err, output)
	}

	fixtures := []struct {
		name       string
		files      map[string]string
		wantPurl   string
		incomplete bool
	}{
		{
			name: "go-mod-and-sum",
			files: map[string]string{
				"go.mod": "module example.com/demo\ngo 1.22\n\nrequire github.com/go-chi/chi/v5 v5.0.12\n",
				"go.sum": "github.com/go-chi/chi/v5 v5.0.12 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\ngithub.com/go-chi/chi/v5 v5.0.12/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
			},
			wantPurl: "pkg:golang/github.com/go-chi/chi/v5@v5.0.12",
		},
		{
			name: "npm-package-lock-v3",
			files: map[string]string{
				"package.json":      `{"name":"demo","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}`,
				"package-lock.json": `{"name":"demo","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"demo","version":"1.0.0","dependencies":{"lodash":"4.17.21"}},"node_modules/lodash":{"version":"4.17.21"}}}`,
			},
			wantPurl: "pkg:npm/lodash@4.17.21",
		},
		{
			name: "npm-package-lock-without-package-json",
			files: map[string]string{
				"package-lock.json": `{"name":"demo","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"demo","version":"1.0.0","dependencies":{"lodash":"4.17.21"}},"node_modules/lodash":{"version":"4.17.21"}}}`,
			},
			wantPurl: "pkg:npm/lodash@4.17.21",
		},
		{
			name: "npm-package-lock-invalid-root",
			files: map[string]string{
				"package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}`,
			},
			incomplete: true,
		},
		{
			name: "npm-scoped-package",
			files: map[string]string{
				"package.json":      `{"name":"demo","dependencies":{"@scope/pkg":"1.2.3"}}`,
				"package-lock.json": `{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"@scope/pkg":"1.2.3"}},"node_modules/@scope/pkg":{"version":"1.2.3"}}}`,
			},
			wantPurl: "pkg:npm/%40scope/pkg@1.2.3",
		},
		{
			name: "npm-workspaces-monorepo",
			files: map[string]string{
				"package.json":              `{"name":"mono","private":true,"workspaces":["packages/*"]}`,
				"package-lock.json":         `{"name":"mono","lockfileVersion":3,"packages":{"":{"name":"mono","workspaces":["packages/*"]},"packages/app":{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.21"}},"node_modules/lodash":{"version":"4.17.21"}}}`,
				"packages/app/package.json": `{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}`,
			},
			wantPurl: "pkg:npm/lodash@4.17.21",
		},
		{
			name: "pnpm-v6-lockfile",
			files: map[string]string{
				"package.json":   `{"name":"demo","dependencies":{"lodash":"4.17.21"}}`,
				"pnpm-lock.yaml": "lockfileVersion: '6.0'\n\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: 4.17.21\n        version: 4.17.21\n\npackages:\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-test}\n",
			},
			wantPurl: "pkg:npm/lodash@4.17.21",
		},
		{
			name: "yarn-v1-lockfile",
			files: map[string]string{
				"package.json": `{"name":"demo","dependencies":{"lodash":"4.17.21"}}`,
				"yarn.lock":    "# yarn lockfile v1\n\nlodash@4.17.21:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n",
			},
			wantPurl: "pkg:npm/lodash@4.17.21",
		},
		{
			name: "bundler-gemfile-lock",
			files: map[string]string{
				"Gemfile":      "source 'https://rubygems.org'\ngem 'rack', '2.2.8'\n",
				"Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.8)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack (= 2.2.8)\n\nBUNDLED WITH\n   2.4.22\n",
			},
			wantPurl: "pkg:gem/rack@2.2.8",
		},
		{
			name: "gradle-groovy-build",
			files: map[string]string{
				"build.gradle": "dependencies { implementation 'com.google.guava:guava:32.1.3-jre' }\n",
			},
			wantPurl: "pkg:maven/com.google.guava/guava@32.1.3-jre",
		},
		{
			name: "nuget-packages-config",
			files: map[string]string{
				"Demo.csproj":     "<Project />",
				"packages.config": `<?xml version="1.0" encoding="utf-8"?><packages><package id="Newtonsoft.Json" version="13.0.1" targetFramework="net45" /></packages>`,
			},
			wantPurl: "pkg:nuget/Newtonsoft.Json@13.0.1",
		},
		{
			name: "maven-pom",
			files: map[string]string{
				"pom.xml": `<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>demo</artifactId><version>1.0</version><dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>32.1.3-jre</version></dependency></dependencies></project>`,
			},
			wantPurl: "pkg:maven/com.google.guava/guava@32.1.3-jre",
		},
		{
			name: "python-requirements",
			files: map[string]string{
				"requirements.txt": "requests==2.31.0\n",
			},
			wantPurl: "pkg:pypi/requests@2.31.0",
		},
		{
			name: "cargo-lock",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = 'demo'\nversion = '0.1.0'\nedition = '2021'\n\n[dependencies]\nserde = '1.0.193'\n",
				"Cargo.lock": "version = 3\n\n[[package]]\nname = 'demo'\nversion = '0.1.0'\ndependencies = [\n 'serde',\n]\n\n[[package]]\nname = 'serde'\nversion = '1.0.193'\nsource = 'registry+https://github.com/rust-lang/crates.io-index'\nchecksum = '0000000000000000000000000000000000000000000000000000000000000000'\n",
			},
			wantPurl: "pkg:cargo/serde@1.0.193",
		},
		{
			name: "composer-lock",
			files: map[string]string{
				"composer.json": `{"name":"example/demo","require":{"monolog/monolog":"2.9.1"}}`,
				"composer.lock": `{"_readme":[],"content-hash":"test","packages":[{"name":"monolog/monolog","version":"2.9.1","source":{"type":"git","url":"https://example.invalid","reference":"abc"},"dist":{"type":"zip","url":"https://example.invalid","reference":"abc","shasum":""},"require":{"php":"^7.2 || ^8.0"},"type":"library"}],"packages-dev":[],"aliases":[],"minimum-stability":"stable","stability-flags":[],"prefer-stable":false,"prefer-lowest":false,"platform":[],"platform-dev":[],"plugin-api-version":"2.6.0"}`,
			},
			wantPurl: "pkg:composer/monolog/monolog@2.9.1",
		},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			project := filepath.Join(t.TempDir(), "project")
			if err := os.MkdirAll(project, 0o755); err != nil {
				t.Fatal(err)
			}
			for name, content := range fixture.files {
				filePath := filepath.Join(project, name)
				if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			sbom := filepath.Join(t.TempDir(), "bom.spdx.json")
			generate := exec.CommandContext(ctx, cli, "--no-log-file", "dfscan", project,
				"--no-build", "--sbom-format", "spdx-json", "--sbom-output", sbom)
			generateOutput, generateErr := generate.CombinedOutput()
			if fixture.incomplete {
				var exitErr *exec.ExitError
				if !errors.As(generateErr, &exitErr) || exitErr.ExitCode() != 1 {
					t.Fatalf("incomplete dependency scan must exit nonzero (err=%v): %s", generateErr, generateOutput)
				}
				data, err := os.ReadFile(sbom)
				if err != nil {
					t.Fatal(err)
				}
				var document struct {
					Packages    []json.RawMessage `json:"packages"`
					Annotations []struct {
						Comment string `json:"comment"`
					} `json:"annotations"`
				}
				if err := json.Unmarshal(data, &document); err != nil {
					t.Fatalf("parse MurphySec SPDX JSON: %v", err)
				}
				if len(document.Packages) != 0 {
					t.Fatalf("lockfile-only scan unexpectedly returned %d packages", len(document.Packages))
				}
				annotated := false
				for _, annotation := range document.Annotations {
					if strings.Contains(annotation.Comment, "inspector_failed") && strings.Contains(annotation.Comment, "dependency data may be incomplete") {
						annotated = true
						break
					}
				}
				if !annotated {
					t.Fatalf("partial SBOM has no inspector failure annotation: %+v", document.Annotations)
				}
				t.Log("partial SBOM is marked and command exits nonzero")
				return
			}
			if generateErr != nil {
				t.Fatalf("generate MurphySec SBOM: %v\n%s", generateErr, generateOutput)
			}

			resultFile := filepath.Join(t.TempDir(), "osv.json")
			scan := exec.CommandContext(ctx, scanner, "scan", "source", "--lockfile", sbom,
				"--format", "json", "--all-packages", "--output-file", resultFile)
			scanOutput, scanErr := scan.CombinedOutput()
			if scanErr != nil {
				var exitErr *exec.ExitError
				if !errors.As(scanErr, &exitErr) {
					t.Fatalf("run osv-scanner: %v\n%s", scanErr, scanOutput)
				}
				if exitErr.ExitCode() != 1 {
					t.Fatalf("osv-scanner failed before producing a usable scan (exit=%d): %s", exitErr.ExitCode(), scanOutput)
				}
				t.Log("osv-scanner reported one or more vulnerabilities")
			}

			data, err := os.ReadFile(resultFile)
			if err != nil {
				t.Fatalf("osv-scanner did not write JSON output (exit=%v): %v\n%s", scanErr, err, scanOutput)
			}
			var result struct {
				Results []struct {
					Packages []struct {
						Package struct {
							PURL string `json:"purl"`
						} `json:"package"`
						Vulnerabilities []struct {
							ID string `json:"id"`
						} `json:"vulnerabilities"`
					} `json:"packages"`
				} `json:"results"`
			}
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatalf("parse osv-scanner JSON: %v", err)
			}
			var purls []string
			var vulnerabilityIDs []string
			for _, source := range result.Results {
				for _, pkg := range source.Packages {
					purls = append(purls, pkg.Package.PURL)
					for _, vulnerability := range pkg.Vulnerabilities {
						vulnerabilityIDs = append(vulnerabilityIDs, vulnerability.ID)
					}
				}
			}
			if !containsString(purls, fixture.wantPurl) {
				t.Fatalf("osv-scanner did not retain expected package %q; got %v (exit=%v): %s",
					fixture.wantPurl, purls, scanErr, strings.TrimSpace(string(scanOutput)))
			}
			sort.Strings(vulnerabilityIDs)
			t.Logf("online OSV result: %d package(s); vulnerability IDs: %v", len(purls), vulnerabilityIDs)
		})
	}

	t.Run("fixed-osv-database-hit-and-no-hit", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "db")
		if err := writeOSVFixtureDatabase(dbPath); err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			version string
			wantID  bool
		}{
			{version: "1.0.0", wantID: true},
			{version: "2.0.0", wantID: false},
		} {
			t.Run(test.version, func(t *testing.T) {
				project := filepath.Join(t.TempDir(), "project")
				if err := os.MkdirAll(project, 0o755); err != nil {
					t.Fatal(err)
				}
				packageFile := `{"name":"fixture","version":"1.0.0","dependencies":{"lodash":"` + test.version + `"}}`
				if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(packageFile), 0o644); err != nil {
					t.Fatal(err)
				}
				lockfile := `{"name":"fixture","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0","dependencies":{"lodash":"` + test.version + `"}},"node_modules/lodash":{"version":"` + test.version + `"}}}`
				if err := os.WriteFile(filepath.Join(project, "package-lock.json"), []byte(lockfile), 0o644); err != nil {
					t.Fatal(err)
				}
				sbom := filepath.Join(t.TempDir(), "fixture.spdx.json")
				generate := exec.CommandContext(ctx, cli, "--no-log-file", "dfscan", project,
					"--no-build", "--sbom-format", "spdx-json", "--sbom-output", sbom)
				if output, err := generate.CombinedOutput(); err != nil {
					t.Fatalf("generate fixture SBOM: %v\n%s", err, output)
				}

				resultFile := filepath.Join(t.TempDir(), "osv.json")
				scan := exec.CommandContext(ctx, scanner, "scan", "source", "--offline", "--local-db-path", dbPath, "--lockfile", sbom,
					"--format", "json", "--all-packages", "--output-file", resultFile)
				output, scanErr := scan.CombinedOutput()
				if scanErr != nil {
					var exitErr *exec.ExitError
					if !errors.As(scanErr, &exitErr) || exitErr.ExitCode() != 1 || !test.wantID {
						t.Fatalf("unexpected osv-scanner result (want finding=%v, err=%v): %s", test.wantID, scanErr, output)
					}
				} else if test.wantID {
					t.Fatalf("expected fixture vulnerability, scanner returned success: %s", output)
				}
				data, err := os.ReadFile(resultFile)
				if err != nil {
					t.Fatalf("read osv-scanner result: %v\n%s", err, output)
				}
				var result struct {
					Results []struct {
						Packages []struct {
							Vulnerabilities []struct {
								ID string `json:"id"`
							} `json:"vulnerabilities"`
						} `json:"packages"`
					} `json:"results"`
				}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatal(err)
				}
				found := false
				for _, source := range result.Results {
					for _, pkg := range source.Packages {
						for _, vuln := range pkg.Vulnerabilities {
							found = found || vuln.ID == "MAL-TEST-2026-0001"
						}
					}
				}
				if found != test.wantID {
					t.Fatalf("fixture vulnerability found=%v, want %v", found, test.wantID)
				}
			})
		}
	})
}

func writeOSVFixtureDatabase(root string) error {
	path := filepath.Join(root, "osv-scalibr", "npm", "all.zip")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	w := zip.NewWriter(file)
	entry, err := w.Create("MAL-TEST-2026-0001.json")
	if err == nil {
		_, err = entry.Write([]byte(`{"schema_version":"1.6.0","id":"MAL-TEST-2026-0001","modified":"2026-01-01T00:00:00Z","published":"2026-01-01T00:00:00Z","summary":"MurphySec compatibility test fixture","affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`))
	}
	closeErr := w.Close()
	fileErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return fileErr
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
