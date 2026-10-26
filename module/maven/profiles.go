package maven

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/murphysecurity/murphysec/infra/logctx"
	"github.com/murphysecurity/murphysec/scanerr"
	"github.com/murphysecurity/murphysec/toolver"
	"github.com/vifraa/gopom"
)

// findPomProfiles walks the reactor using both regular and profile-declared
// modules. Any malformed POM is an error so Maven is not run with an
// incomplete -P list.
func findPomProfiles(ctx context.Context, rootPomPath string) ([]string, error) {
	queue := []string{rootPomPath}
	visited := map[string]bool{}
	seenProfiles := map[string]bool{}
	var profiles []string

	for len(queue) > 0 {
		pomPath := filepath.Clean(queue[0])
		queue = queue[1:]
		key, err := filepath.Abs(pomPath)
		if err != nil {
			return nil, err
		}
		key = filepath.Clean(key)
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if visited[key] {
			continue
		}
		visited[key] = true

		project, err := readPomFile(ctx, pomPath)
		if err != nil {
			return nil, fmt.Errorf("read Maven POM %s: %w", pomPath, err)
		}
		for _, profile := range project.Profiles {
			id := strings.TrimSpace(profile.ID)
			if id != "" && !seenProfiles[id] {
				profiles = append(profiles, id)
				seenProfiles[id] = true
			}
		}

		modules := append([]string(nil), project.Modules...)
		for _, profile := range project.Profiles {
			modules = append(modules, profile.Modules...)
		}
		for _, module := range modules {
			modulePath := filepath.Join(filepath.Dir(pomPath), module)
			if filepath.Ext(modulePath) == ".xml" {
				queue = append(queue, modulePath)
			} else {
				queue = append(queue, filepath.Join(modulePath, "pom.xml"))
			}
		}
	}
	return profiles, nil
}

func activeMavenProfiles(ctx context.Context, project *gopom.Project, pomPath string) []gopom.Profile {
	mavenConfig := toolver.Get(ctx).Maven
	args := append(append([]string(nil), mavenConfig.AdditionalPrependArgs...), mavenConfig.AdditionalArgs...)
	return selectMavenProfiles(ctx, project, pomPath, args)
}

func selectMavenProfiles(ctx context.Context, project *gopom.Project, pomPath string, args []string) []gopom.Profile {
	logger := logctx.Use(ctx)
	explicit, disabled, systemProperties := parseMavenProfileArgs(args)
	baseDir := filepath.Dir(pomPath)

	var active, defaults []gopom.Profile
	for _, profile := range project.Profiles {
		if disabled[profile.ID] {
			continue
		}
		if explicit[profile.ID] || profileActivationMatches(ctx, profile.Activation, baseDir, systemProperties) {
			active = append(active, profile)
		} else if profile.Activation.ActiveByDefault {
			defaults = append(defaults, profile)
		}
	}
	if len(active) == 0 {
		active = defaults
	}
	if len(active) == 0 && len(project.Profiles) > 0 {
		logger.Debug("No Maven profiles are active in static resolver")
	}
	return active
}

func parseMavenProfileArgs(args []string) (explicit, disabled map[string]bool, properties map[string]string) {
	explicit, disabled, properties = map[string]bool{}, map[string]bool{}, map[string]string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		var profileList string
		switch {
		case arg == "-P" || arg == "--activate-profiles":
			if i+1 < len(args) {
				i++
				profileList = args[i]
			}
		case strings.HasPrefix(arg, "-P") && len(arg) > 2:
			profileList = strings.TrimPrefix(arg, "-P")
		case strings.HasPrefix(arg, "--activate-profiles="):
			profileList = strings.TrimPrefix(arg, "--activate-profiles=")
		case strings.HasPrefix(arg, "-D") && len(arg) > 2:
			key, value, ok := strings.Cut(strings.TrimPrefix(arg, "-D"), "=")
			if ok {
				properties[key] = value
			} else {
				properties[key] = "true"
			}
		}
		for _, raw := range strings.Split(profileList, ",") {
			id := strings.TrimSpace(raw)
			if id == "" {
				continue
			}
			if strings.HasPrefix(id, "!") || strings.HasPrefix(id, "-") {
				disabled[id[1:]] = true
				delete(explicit, id[1:])
			} else if !disabled[id] {
				explicit[id] = true
			}
		}
	}
	return
}

func profileActivationMatches(ctx context.Context, a gopom.Activation, baseDir string, properties map[string]string) bool {
	if a.JDK != "" {
		version := configuredJavaVersion(ctx)
		if version == "" || !matchesMavenJDK(a.JDK, version) {
			return false
		}
	}
	if a.OS.Name != "" && !matchesMavenOS(a.OS.Name, runtime.GOOS) {
		return false
	}
	if a.OS.Family != "" && !matchesOSFamily(a.OS.Family) {
		return false
	}
	if a.OS.Arch != "" && !matchesMavenArch(a.OS.Arch, runtime.GOARCH) {
		return false
	}
	if a.OS.Version != "" {
		return false
	}
	if a.Property.Name != "" && !matchesActivationProperty(a.Property, properties) {
		return false
	}
	if a.File.Exists != "" && !activationFileExists(a.File.Exists, baseDir) {
		return false
	}
	if a.File.Missing != "" && activationFileExists(a.File.Missing, baseDir) {
		return false
	}
	return a.JDK != "" || a.OS.Name != "" || a.OS.Family != "" || a.OS.Arch != "" || a.OS.Version != "" ||
		a.Property.Name != "" || a.File.Exists != "" || a.File.Missing != ""
}

func configuredJavaVersion(ctx context.Context) string {
	config := toolver.Get(ctx).Maven
	if config.JdkVersion != "" {
		return config.JdkVersion
	}
	if version := os.Getenv("JAVA_VERSION"); version != "" {
		return version
	}
	java := "java"
	if config.JavaHome != "" {
		java = filepath.Join(config.JavaHome, "bin", "java")
		if runtime.GOOS == "windows" {
			java += ".exe"
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	versionCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(versionCtx, java, "-version").CombinedOutput()
	if err != nil {
		return ""
	}
	match := regexp.MustCompile(`version "([^"]+)"`).FindSubmatch(output)
	if len(match) == 2 {
		return string(match[1])
	}
	return ""
}

func matchesMavenJDK(spec, version string) bool {
	negated := strings.HasPrefix(spec, "!")
	if negated {
		spec = strings.TrimPrefix(spec, "!")
	}
	match := false
	if strings.HasPrefix(spec, "[") || strings.HasPrefix(spec, "(") {
		match = matchesVersionRange(spec, version)
	} else {
		match = strings.HasPrefix(version, spec)
	}
	return match != negated
}

func matchesVersionRange(spec, version string) bool {
	if len(spec) < 3 {
		return false
	}
	parts := strings.SplitN(spec[1:len(spec)-1], ",", 2)
	if len(parts) != 2 {
		return false
	}
	lowerOK, upperOK := true, true
	if parts[0] != "" {
		cmp, ok := compareVersions(version, parts[0])
		lowerOK = ok && (cmp > 0 || (cmp == 0 && spec[0] == '['))
	}
	if parts[1] != "" {
		cmp, ok := compareVersions(version, parts[1])
		upperOK = ok && (cmp < 0 || (cmp == 0 && spec[len(spec)-1] == ']'))
	}
	return lowerOK && upperOK
}

func compareVersions(a, b string) (int, bool) {
	parse := func(value string) ([]int, bool) {
		parts := strings.Split(value, ".")
		out := make([]int, len(parts))
		for i, part := range parts {
			digits := regexp.MustCompile(`^\d+`).FindString(part)
			if digits == "" {
				return nil, false
			}
			value, err := strconv.Atoi(digits)
			if err != nil {
				return nil, false
			}
			out[i] = value
		}
		return out, true
	}
	left, ok := parse(a)
	if !ok {
		return 0, false
	}
	right, ok := parse(b)
	if !ok {
		return 0, false
	}
	for i := 0; i < len(left) || i < len(right); i++ {
		l, r := 0, 0
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		if l < r {
			return -1, true
		}
		if l > r {
			return 1, true
		}
	}
	return 0, true
}

func matchesMavenOS(spec, current string) bool {
	negated := strings.HasPrefix(spec, "!")
	if negated {
		spec = strings.TrimPrefix(spec, "!")
	}
	match := strings.EqualFold(spec, current)
	if current == "darwin" {
		match = match || strings.EqualFold(spec, "mac os x") || strings.EqualFold(spec, "mac")
	}
	if current == "windows" {
		match = match || strings.EqualFold(spec, "win")
	}
	return match != negated
}

func matchesOSFamily(family string) bool {
	negated := strings.HasPrefix(family, "!")
	if negated {
		family = strings.TrimPrefix(family, "!")
	}
	family = strings.ToLower(family)
	match := (family == "windows" && runtime.GOOS == "windows") ||
		(family == "unix" && runtime.GOOS != "windows") ||
		((family == "mac" || family == "mac os x") && runtime.GOOS == "darwin")
	return match != negated
}

func matchesMavenArch(spec, arch string) bool {
	negated := strings.HasPrefix(spec, "!")
	if negated {
		spec = strings.TrimPrefix(spec, "!")
	}
	aliases := map[string]string{"amd64": "x86_64", "386": "x86", "arm64": "aarch64"}
	if alias := aliases[arch]; alias != "" {
		arch = alias
	}
	return strings.EqualFold(spec, arch) != negated
}

func matchesActivationProperty(a gopom.ActivationProperty, properties map[string]string) bool {
	name := a.Name
	if strings.HasPrefix(name, "!") {
		_, exists := activationPropertyValue(strings.TrimPrefix(name, "!"), properties)
		return !exists
	}
	value, exists := activationPropertyValue(name, properties)
	if !exists {
		return false
	}
	if a.Value == "" {
		return true
	}
	negated := strings.HasPrefix(a.Value, "!")
	match := value == strings.TrimPrefix(a.Value, "!")
	return match != negated
}

func activationPropertyValue(name string, properties map[string]string) (string, bool) {
	if value, ok := properties[name]; ok {
		return value, true
	}
	if strings.HasPrefix(name, "env.") {
		return os.LookupEnv(strings.TrimPrefix(name, "env."))
	}
	return "", false
}

func activationFileExists(spec, baseDir string) bool {
	path := strings.ReplaceAll(spec, "${basedir}", baseDir)
	path = strings.ReplaceAll(path, "${user.home}", mustUserHome())
	path = os.Expand(path, func(key string) string {
		if strings.HasPrefix(key, "env.") {
			return os.Getenv(strings.TrimPrefix(key, "env."))
		}
		return "${" + key + "}"
	})
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	_, err := os.Stat(path)
	return err == nil
}

func mustUserHome() string {
	home, _ := os.UserHomeDir()
	return home
}

func reportUnsupportedProfileActivation(ctx context.Context, pomPath string, profile gopom.Profile) {
	var reasons []string
	a := profile.Activation
	if a.OS.Version != "" {
		reasons = append(reasons, "OS version")
	}
	if a.JDK != "" && configuredJavaVersion(ctx) == "" {
		reasons = append(reasons, "JDK version (Java runtime not detected)")
	}
	if (a.File.Exists != "" || a.File.Missing != "") && strings.ContainsAny(a.File.Exists+a.File.Missing, "${") {
		path := a.File.Exists + a.File.Missing
		if strings.Contains(path, "${") && !strings.Contains(path, "${basedir}") && !strings.Contains(path, "${user.home}") && !strings.Contains(path, "${env.") {
			reasons = append(reasons, "unresolved file path")
		}
	}
	if len(reasons) == 0 {
		return
	}
	scanerr.Add(ctx, scanerr.Param{
		Kind:    scanerr.KindMavenProfileActivationUnknown,
		Content: fmt.Sprintf("profile %q in %s has unresolved activation condition(s): %s", profile.ID, pomPath, strings.Join(reasons, ", ")),
	})
}
