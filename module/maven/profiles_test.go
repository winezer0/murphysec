package maven

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/murphysecurity/murphysec/scanerr"
	"github.com/vifraa/gopom"
)

func writeProfilePom(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFindPomProfilesAndPassesThemToMaven(t *testing.T) {
	ctx := context.Background()
	pomPath := filepath.Join(t.TempDir(), "pom.xml")
	writeProfilePom(t, pomPath, `
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>root</artifactId><version>1</version>
  <profiles>
    <profile><id>linux-build</id></profile>
    <profile><id>with-extra-deps</id></profile>
  </profiles>
</project>`)

	profiles, err := findPomProfiles(ctx, pomPath)
	if err != nil {
		t.Fatalf("findPomProfiles returned error: %v", err)
	}
	if want := []string{"linux-build", "with-extra-deps"}; !reflect.DeepEqual(profiles, want) {
		t.Fatalf("profiles = %v, want %v", profiles, want)
	}

	args := appendMavenProfileArgs([]string{"dependency:tree"}, profiles)
	wantArgs := []string{"dependency:tree", "-P", "linux-build,with-extra-deps"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("Maven args = %v, want %v", args, wantArgs)
	}
}

func TestFindPomProfilesReturnsParseError(t *testing.T) {
	pomPath := filepath.Join(t.TempDir(), "pom.xml")
	writeProfilePom(t, pomPath, `<project><profiles><profile><id>broken</profiles></project>`)
	if _, err := findPomProfiles(context.Background(), pomPath); err == nil {
		t.Fatal("findPomProfiles should return an error for malformed XML")
	}
}

func TestScanDepsByPluginCommandReportsMalformedReactorPOM(t *testing.T) {
	ctx := scanerr.WithCtx(context.Background())
	root := t.TempDir()
	writeProfilePom(t, filepath.Join(root, "pom.xml"), `<project><profiles><profile><id>broken</profiles></project>`)

	if _, err := ScanDepsByPluginCommand(ctx, root, nil); err == nil {
		t.Fatal("expected malformed POM to stop Maven graph scan")
	}
	for _, warning := range scanerr.GetAll(ctx) {
		if warning.Kind == scanerr.KindMavenProfileResolution {
			return
		}
	}
	t.Fatal("expected profile resolution diagnostic for malformed POM")
}

func TestFindPomProfilesIncludesReactorModuleProfiles(t *testing.T) {
	root := t.TempDir()
	writeProfilePom(t, filepath.Join(root, "pom.xml"), `
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>root</artifactId><version>1</version>
  <modules><module>child</module></modules>
  <profiles>
    <profile><id>root-profile</id><modules><module>extra</module></modules></profile>
  </profiles>
</project>`)
	writeProfilePom(t, filepath.Join(root, "extra", "pom.xml"), `
<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>extra</artifactId><version>1</version>
  <profiles><profile><id>profile-module-profile</id></profile></profiles>
</project>`)
	writeProfilePom(t, filepath.Join(root, "child", "pom.xml"), `
<project>
  <modelVersion>4.0.0</modelVersion>
  <parent><groupId>example</groupId><artifactId>root</artifactId><version>1</version></parent>
  <artifactId>child</artifactId>
  <profiles><profile><id>child-profile</id></profile></profiles>
</project>`)

	profiles, err := findPomProfiles(context.Background(), filepath.Join(root, "pom.xml"))
	if err != nil {
		t.Fatalf("findPomProfiles returned error: %v", err)
	}
	if want := []string{"root-profile", "child-profile", "profile-module-profile"}; !reflect.DeepEqual(profiles, want) {
		t.Fatalf("profiles = %v, want reactor profiles %v", profiles, want)
	}
}

func TestStaticResolverIncludesProfileDependencies(t *testing.T) {
	ctx := scanerr.WithCtx(context.Background())
	pomPath := filepath.Join(t.TempDir(), "pom.xml")
	writeProfilePom(t, pomPath, `
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>root</artifactId><version>1</version>
  <profiles>
    <profile>
      <id>extra-deps</id>
      <activation><activeByDefault>true</activeByDefault></activation>
      <properties><profile.dep.version>1.2.3</profile.dep.version></properties>
      <dependencyManagement>
        <dependencies>
          <dependency><groupId>example.lib</groupId><artifactId>profile-only</artifactId><version>${profile.dep.version}</version></dependency>
        </dependencies>
      </dependencyManagement>
      <dependencies>
        <dependency><groupId>example.lib</groupId><artifactId>profile-only</artifactId></dependency>
      </dependencies>
    </profile>
    <profile>
      <id>inactive</id>
      <dependencies>
        <dependency><groupId>example.lib</groupId><artifactId>must-not-appear</artifactId><version>9.9.9</version></dependency>
      </dependencies>
    </profile>
  </profiles>
</project>`)

	project, err := readPomFile(ctx, pomPath)
	if err != nil {
		t.Fatalf("read profile POM: %v", err)
	}
	resolver := NewPomResolver(ctx, nil)
	resolver.addPom(&UnresolvedPom{Project: project, Path: pomPath})
	resolved, err := resolver.ResolvePom(ctx, Coordinate{GroupId: "example", ArtifactId: "root", Version: "1"})
	if err != nil {
		t.Fatalf("resolve project POM: %v", err)
	}

	for _, dep := range resolved.ListDependencies() {
		if dep.GroupID == "example.lib" && dep.ArtifactID == "profile-only" {
			if dep.Version != "1.2.3" {
				t.Fatalf("profile dependency version = %q, want 1.2.3", dep.Version)
			}
			for _, other := range resolved.ListDependencies() {
				if other.ArtifactID == "must-not-appear" {
					t.Fatal("static resolver included a profile that is not active")
				}
			}
			return
		}
	}
	t.Fatal("static resolver omitted dependency declared only inside a profile")
}

func TestMavenProfileSelectionHonorsExplicitAndDisabledIDs(t *testing.T) {
	project := &gopom.Project{Profiles: []gopom.Profile{
		{ID: "selected"},
		{ID: "disabled", Activation: gopom.Activation{ActiveByDefault: true}},
		{ID: "other", Activation: gopom.Activation{ActiveByDefault: true}},
	}}
	profiles := selectMavenProfiles(context.Background(), project, "pom.xml", []string{"-P", "selected,!disabled"})
	if got, want := profileIDs(profiles), []string{"selected"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected profiles = %v, want %v", got, want)
	}
}

func TestMavenProfileActivationConditions(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(baseDir, "present.flag"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JAVA_VERSION", "21.0.3")
	t.Setenv("PROFILE_ENV_FLAG", "yes")
	ctx := context.Background()
	properties := map[string]string{"feature.enabled": "true"}

	cases := []struct {
		name       string
		activation gopom.Activation
		want       bool
	}{
		{name: "jdk range", activation: gopom.Activation{JDK: "[17,)"}, want: true},
		{name: "jdk mismatch", activation: gopom.Activation{JDK: "1.8"}},
		{name: "property value", activation: gopom.Activation{Property: gopom.ActivationProperty{Name: "feature.enabled", Value: "true"}}, want: true},
		{name: "negated property value", activation: gopom.Activation{Property: gopom.ActivationProperty{Name: "feature.enabled", Value: "!false"}}, want: true},
		{name: "environment property", activation: gopom.Activation{Property: gopom.ActivationProperty{Name: "env.PROFILE_ENV_FLAG", Value: "yes"}}, want: true},
		{name: "OS family", activation: gopom.Activation{OS: gopom.ActivationOS{Family: currentOSFamily()}}, want: true},
		{name: "OS architecture", activation: gopom.Activation{OS: gopom.ActivationOS{Arch: currentMavenArch()}}, want: true},
		{name: "file exists", activation: gopom.Activation{File: gopom.ActivationFile{Exists: "${basedir}/present.flag"}}, want: true},
		{name: "file missing", activation: gopom.Activation{File: gopom.ActivationFile{Missing: "absent.flag"}}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := profileActivationMatches(ctx, tc.activation, baseDir, properties); got != tc.want {
				t.Fatalf("profileActivationMatches() = %v, want %v", got, tc.want)
			}
		})
	}
}

func currentOSFamily() string {
	if runtime.GOOS == "windows" {
		return "windows"
	}
	if runtime.GOOS == "darwin" {
		return "mac"
	}
	return "unix"
}

func currentMavenArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "386":
		return "x86"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}

func profileIDs(profiles []gopom.Profile) []string {
	ids := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		ids = append(ids, profile.ID)
	}
	return ids
}

func TestStaticResolverReportsUnsupportedProfileActivation(t *testing.T) {
	ctx := scanerr.WithCtx(context.Background())
	pomPath := filepath.Join(t.TempDir(), "pom.xml")
	writeProfilePom(t, pomPath, `
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>root</artifactId><version>1</version>
  <profiles>
    <profile><id>os-version</id><activation><os><version>99.0</version></os></activation></profile>
  </profiles>
</project>`)
	project, err := readPomFile(ctx, pomPath)
	if err != nil {
		t.Fatalf("read profile POM: %v", err)
	}
	resolver := NewPomResolver(ctx, nil)
	resolver.addPom(&UnresolvedPom{Project: project, Path: pomPath})
	if _, err = resolver.ResolvePom(ctx, Coordinate{GroupId: "example", ArtifactId: "root", Version: "1"}); err != nil {
		t.Fatalf("resolve project POM: %v", err)
	}

	warnings := scanerr.GetAll(ctx)
	for _, warning := range warnings {
		if warning.Kind == scanerr.KindMavenProfileActivationUnknown {
			return
		}
	}
	t.Fatalf("expected unsupported profile activation diagnostic, got %v", warnings)
}
