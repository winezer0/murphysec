package resolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/murphysecurity/murphysec/env"
	"github.com/murphysecurity/murphysec/module/python/requirements"
	"go.uber.org/zap"
)

const pipConf = "[global]\nindex-url = https://%s/simple/\ntrusted-host = %s"
const maxRequirementsSize = 64 * 1024

type pipdeptreeEntry struct {
	Key              string            `json:"key"`
	InstalledVersion string            `json:"installed_version"`
	Dependencies     []pipdeptreeEntry `json:"dependencies"`
}

// Dependency is a resolved Python package and its transitive dependency graph.
type Dependency struct {
	Name         string
	Version      string
	Dependencies []Dependency
}

// BuildDependencyTree resolves inferred Python imports in an isolated temporary
// environment. The returned graph includes declared direct dependencies even
// when package installation omits them from pipdeptree output.
func BuildDependencyTree(ctx context.Context, interpreter, projectDir string, directVersions map[string]string, logger *zap.SugaredLogger) ([]Dependency, error) {
	if interpreter == "" {
		return nil, ErrPythonUnavailable
	}
	var dependencies []Dependency
	err := withTemporaryWorkspace("", func(workspace string) error {
		var err error
		dependencies, err = buildInWorkspace(ctx, workspace, interpreter, projectDir, directVersions, logger)
		return err
	})
	return dependencies, err
}

func buildInWorkspace(ctx context.Context, workspace, interpreter, projectDir string, directVersions map[string]string, logger *zap.SugaredLogger) ([]Dependency, error) {
	venvDir := filepath.Join(workspace, "venv")
	if err := run(ctx, projectDir, interpreter, "-m", "venv", venvDir); err != nil {
		return nil, fmt.Errorf("create Python virtual environment: %w", err)
	}
	venvPython := venvPythonPath(venvDir)
	if env.PIP_SOURCE_ADDR != "" {
		logger.Debug("using configured private Python package index")
		if err := writePipConfig(venvDir, env.PIP_SOURCE_ADDR); err != nil {
			return nil, fmt.Errorf("configure Python package index: %w", err)
		}
	}
	if err := run(ctx, workspace, venvPython, "-m", "pip", "install", "--upgrade", "pip"); err != nil {
		return nil, fmt.Errorf("upgrade pip: %w", err)
	}

	generatedRequirements := filepath.Join(workspace, "requirements.txt")
	if err := installPipPackage(ctx, workspace, venvPython, "pipreqs"); err != nil {
		return nil, fmt.Errorf("install pipreqs: %w", err)
	}
	if err := run(ctx, workspace, venvCommandPath(venvDir, "pipreqs"), projectDir, "--savepath", generatedRequirements, "--encoding=utf-8", "--ignore=virtual_venv"); err != nil {
		return nil, fmt.Errorf("infer Python requirements: %w", err)
	}
	generated, err := readRequirements(generatedRequirements)
	if err != nil {
		return nil, fmt.Errorf("read inferred requirements: %w", err)
	}
	if err := installInferredRequirements(ctx, workspace, venvPython, generated, directVersions, logger); err != nil {
		return nil, err
	}
	installDeclaredRequirements(ctx, workspace, venvPython, directVersions, logger)

	if err := installPipPackage(ctx, workspace, venvPython, "pipdeptree"); err != nil {
		return nil, fmt.Errorf("install pipdeptree: %w", err)
	}
	output, err := runOutput(ctx, workspace, venvCommandPath(venvDir, "pipdeptree"), "--json-tree")
	if err != nil {
		return nil, fmt.Errorf("run pipdeptree: %w", err)
	}
	var tree []pipdeptreeEntry
	if err := json.Unmarshal(output, &tree); err != nil {
		return nil, fmt.Errorf("parse pipdeptree output: %w", err)
	}
	var result []Dependency
	for _, entry := range tree {
		if entry.Key == "" || isResolverTool(entry.Key) {
			continue
		}
		result = append(result, toDependency(entry))
	}
	for name, version := range directVersions {
		appendDirectDependency(&result, name, version)
	}
	for name, version := range generated {
		appendDirectDependency(&result, name, version)
	}
	return result, nil
}

func installInferredRequirements(ctx context.Context, workspace, venvPython string, inferred, direct map[string]string, logger *zap.SugaredLogger) error {
	for _, name := range sortedNames(inferred) {
		version := inferred[name]
		if directVersion, ok := direct[name]; ok && directVersion != "" {
			logger.Debugw("skip inferred install for declared dependency", "package", name, "version", directVersion)
			continue
		}
		args := []string{"-m", "pip", "install", name}
		if version != "" {
			args[len(args)-1] += "==" + version
		}
		if err := run(ctx, workspace, venvPython, args...); err != nil {
			logger.Warnw("install inferred Python dependency failed", "package", name, "error", err)
		}
	}
	return nil
}

func installDeclaredRequirements(ctx context.Context, workspace, venvPython string, direct map[string]string, logger *zap.SugaredLogger) {
	for _, name := range sortedNames(direct) {
		version := direct[name]
		if version == "" || isResolverTool(name) {
			continue
		}
		if err := run(ctx, workspace, venvPython, "-m", "pip", "install", name+"=="+version); err != nil {
			logger.Warnw("install declared Python dependency failed", "package", name, "version", version, "error", err)
		}
	}
}

func sortedNames(packages map[string]string) []string {
	names := make([]string, 0, len(packages))
	for name := range packages {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func installPipPackage(ctx context.Context, workspace, pythonPath, name string) error {
	return run(ctx, workspace, pythonPath, "-m", "pip", "install", name)
}

func run(ctx context.Context, dir, executable string, args ...string) error {
	_, err := runOutput(ctx, dir, executable, args...)
	return err
}

func runOutput(ctx context.Context, dir, executable string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = dir
	cmd.Env = pipEnvironment()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", executable, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func pipEnvironment() []string {
	const key = "PIP_DEFAULT_TIMEOUT="
	environment := os.Environ()
	filtered := environment[:0]
	for _, item := range environment {
		if !strings.HasPrefix(strings.ToUpper(item), key) {
			filtered = append(filtered, item)
		}
	}
	return append(filtered, key+"120")
}

func writePipConfig(venvDir, privateAddr string) error {
	name := "pip.conf"
	if runtime.GOOS == "windows" {
		name = "pip.ini"
	}
	return os.WriteFile(filepath.Join(venvDir, name), []byte(fmt.Sprintf(pipConf, privateAddr, privateAddr)), 0600)
}

func venvPythonPath(venvDir string) string {
	name := "python"
	if runtime.GOOS == "windows" {
		name += ".exe"
		return filepath.Join(venvDir, "Scripts", name)
	}
	return filepath.Join(venvDir, "bin", name)
}

func venvCommandPath(venvDir, name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
		return filepath.Join(venvDir, "Scripts", name)
	}
	return filepath.Join(venvDir, "bin", name)
}

func readRequirements(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRequirementsSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRequirementsSize {
		return nil, fmt.Errorf("requirements file exceeds %d bytes", maxRequirementsSize)
	}
	return requirements.Parse(string(data)), nil
}

func toDependency(entry pipdeptreeEntry) Dependency {
	item := Dependency{Name: entry.Key, Version: entry.InstalledVersion}
	for _, child := range entry.Dependencies {
		item.Dependencies = append(item.Dependencies, toDependency(child))
	}
	return item
}

func appendDirectDependency(items *[]Dependency, name, version string) {
	if name == "" || isResolverTool(name) {
		return
	}
	for _, item := range *items {
		if item.Name == name {
			return
		}
	}
	*items = append(*items, Dependency{Name: name, Version: version})
}

func isResolverTool(name string) bool {
	return name == "pip" || name == "pipreqs" || name == "pipdeptree"
}

func withTemporaryWorkspace(parent string, resolve func(string) error) (resultErr error) {
	workspace, err := os.MkdirTemp(parent, "murphysec-python-")
	if err != nil {
		return fmt.Errorf("create temporary Python workspace: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(workspace); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove temporary Python workspace: %w", err))
		}
	}()
	return resolve(workspace)
}
