package python

import (
	"context"
	"errors"
	"github.com/murphysecurity/murphysec/infra/logctx"
	"github.com/murphysecurity/murphysec/infra/pathignore"
	"github.com/murphysecurity/murphysec/model"
	"github.com/murphysecurity/murphysec/module/python/buildout"
	"github.com/murphysecurity/murphysec/module/python/requirements"
	"github.com/murphysecurity/murphysec/module/python/resolver"
	"github.com/murphysecurity/murphysec/scanerr"
	"github.com/murphysecurity/murphysec/utils"
	"github.com/repeale/fp-go"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Inspector struct{}

type pythonDependency struct {
	name        string
	version     string
	declaration string
}

func (i Inspector) SupportFeature(feature model.InspectorFeature) bool {
	return false
}

func (i Inspector) String() string {
	return "Python"
}

func (i Inspector) CheckDir(ctx context.Context, dir string) bool {
	if buildout.DirHasBuildout(dir) {
		return true
	}
	r, e := os.ReadDir(dir)
	if e == nil {
		for _, it := range r {
			if it.IsDir() {
				continue
			}
			name := it.Name()
			if name == "conanfile.py" {
				continue
			}
			if isRequirementsFile(name) {
				return true
			}
			if filepath.Ext(name) == ".py" {
				return true
			}
		}
	}
	return false
}

func (i Inspector) InspectProject(ctx context.Context) error {
	logger := logctx.Use(ctx).Sugar()
	task := model.UseInspectionTask(ctx)
	dir := task.Dir()
	canResolve := !task.IsNoBuild()
	pythonPath := ""
	if canResolve {
		var err error
		pythonPath, err = resolver.FindPython(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !errors.Is(err, resolver.ErrPythonUnavailable) {
				return err
			}
			canResolve = false
			diagnostic := "Python environment resolution unavailable; using manifest-only dependencies: " + err.Error()
			logger.Warn(diagnostic)
			scanerr.Add(ctx, scanerr.Param{Kind: scanerr.KindPythonResolutionDegraded, Content: diagnostic})
		}
	}
	if canResolve && buildout.DirHasBuildout(dir) {
		if err := buildout.InspectProject(ctx, dir); err != nil {
			logger.Warnf("buildout inspect project fail: %s", err.Error())
		}
	}
	var hostVersionLookup func(context.Context) (map[string]string, error)
	if canResolve {
		hostVersionLookup = resolver.HostPackageVersions
	}
	info, e := collectDepsInfo(ctx, dir, hostVersionLookup)
	if e != nil {
		return e
	}
	if len(info) == 0 {
		logger.Infof("found no deps, omit module")
		return nil
	}

	m := model.Module{
		ModuleName:     filepath.ToSlash(model.UseInspectionTask(ctx).RelDir()),
		PackageManager: "pip",
		ModulePath:     filepath.Join(dir, "Python"),
	}

	var directVersions = make(map[string]string, len(info))
	for _, dependency := range info {
		var di model.DependencyItem
		di.CompName = dependency.name
		di.CompVersion = dependency.version
		di.DeclaredVersion = dependency.declaration
		di.EcoRepo = EcoRepo
		directVersions[dependency.name] = dependency.version
		m.Dependencies = append(m.Dependencies, di)
	}
	if canResolve {
		if hasConflictingVersions(info) || hasRangeDeclarations(info) {
			logger.Warn("skip Python environment resolution because requirements manifests select multiple versions of the same package")
			model.UseInspectionTask(ctx).AddModule(m)
			return nil
		}
		deps, err := resolver.BuildDependencyTree(ctx, pythonPath, dir, directVersions, logger)
		if err != nil {
			logger.Warn("construction failed, enable basic scanning")
			model.UseInspectionTask(ctx).AddModule(m)
			return err
		} else {
			m.Dependencies = toModelDependencies(deps)
		}
	}
	model.UseInspectionTask(ctx).AddModule(m)
	return nil
}

func toModelDependencies(dependencies []resolver.Dependency) []model.DependencyItem {
	result := make([]model.DependencyItem, 0, len(dependencies))
	for _, dependency := range dependencies {
		result = append(result, toModelDependency(dependency, model.DependencyRelationDirect))
	}
	return result
}

func toModelDependency(dependency resolver.Dependency, relation model.DependencyRelation) model.DependencyItem {
	item := model.DependencyItem{
		Component: model.Component{
			CompName: dependency.Name, CompVersion: dependency.Version, EcoRepo: EcoRepo,
		},
		DependencyRelation: relation,
	}
	for _, child := range dependency.Dependencies {
		item.Dependencies = append(item.Dependencies, toModelDependency(child, model.DependencyRelationTransitive))
	}
	return item
}

var EcoRepo = model.EcoRepo{
	Ecosystem:  "pypi",
	Repository: "",
}

var requirementPattern = regexp.MustCompile(`^requirement.*\.txt$`)

func isRequirementsFile(filename string) bool {
	return requirementPattern.MatchString(strings.ToLower(filename))
}

func isDockerfile(filename string) bool {
	return strings.Contains(strings.ToLower(filename), "dockerfile")
}

func dirIgnore(name string) bool {
	return name == "" || name[0] == '.' || pathignore.DirName(name)
}

func collectDepsInfo(ctx context.Context, dir string, hostVersionLookup func(context.Context) (map[string]string, error)) ([]pythonDependency, error) {
	var logger = logctx.Use(ctx).Sugar()
	var task = model.UseInspectionTask(ctx)
	if !filepath.IsAbs(dir) {
		panic("dir must be absolute")
	}
	var noVersionComps = make(map[string]struct{})
	var versionedComps = make(map[pythonDependency]struct{})
	var versionedNames = make(map[string]struct{})
	var unknownVersionComps = make(map[string]struct{})
	e := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return err
		}
		filename := d.Name()
		if d.IsDir() {
			if dirIgnore(filename) {
				return filepath.SkipDir
			}
			return nil
		}
		// ignore conan.py
		if filename == "" || filename[0] == '.' || filename == "conan.py" {
			return nil
		}
		if isDockerfile(filename) {
			data, e := readTextFile(path, 64*1024) // Dockerfile max 64K
			if e != nil {
				logger.Warnf("read dockerfile: %s %v", path, e)
				return nil
			}
			for _, s := range parseDockerfilePipInstall(string(data)) {
				noVersionComps[s] = struct{}{}
			}
			return nil
		}
		if isRequirementsFile(filename) {
			data, e := readTextFile(path, 64*1024)
			if e != nil {
				logger.Warnf("read requirement: %s %v", path, e)
				return nil
			}
			declarations := requirements.Declarations(string(data))
			for k, v := range requirements.Parse(string(data)) {
				constraint := declarations[k]
				if v == "" {
					versionedComps[pythonDependency{name: k, declaration: constraint}] = struct{}{}
					versionedNames[k] = struct{}{}
				} else {
					versionedComps[pythonDependency{name: k, version: v, declaration: constraint}] = struct{}{}
					versionedNames[k] = struct{}{}
				}
			}
			return nil
		}
		if filepath.Ext(filename) == ".py" {
			data, e := readTextFile(path, 256*1024)
			if e != nil {
				logger.Warnf("read py: %s %v", path, e)
				return nil
			}
			for _, line := range strings.Split(string(data), "\n") {
				for _, s := range parsePyImport(line) {
					if !pyPkgBlackList[s] {
						unknownVersionComps[s] = struct{}{}
					}
				}
			}
		}
		return nil
	})
	if e != nil {
		logger.Warnf("walk error: %v", e)
	}
	// merge unknown version components
	for s := range unknownVersionComps {
		if _, ok := versionedNames[s]; ok {
			delete(unknownVersionComps, s)
		}
	}
	if hostVersionLookup != nil && !task.IsNoBuild() && !task.IsInternalCmd() && len(unknownVersionComps) != 0 {
		// try to resolve version from pip list
		m, e := hostVersionLookup(ctx)
		if e != nil {
			m = make(map[string]string)
		}
		for s := range unknownVersionComps {
			if m[s] == "" {
				versionedComps[pythonDependency{name: s}] = struct{}{}
				continue
			}
			versionedComps[pythonDependency{name: s, version: m[s]}] = struct{}{}
			versionedNames[s] = struct{}{}
		}
	} else {
		for s := range unknownVersionComps {
			versionedComps[pythonDependency{name: s}] = struct{}{}
		}
	}
	for s := range noVersionComps {
		if _, ok := versionedNames[s]; ok {
			continue
		}
		versionedComps[pythonDependency{name: s}] = struct{}{}
	}

	var result []pythonDependency
	for component := range versionedComps {
		result = append(result, component)
	}
	// remove component name that match a directory
	result = fp.Filter(func(it pythonDependency) bool {
		var p = it.name
		if p == "" {
			return true
		}
		return !utils.IsDir(filepath.Join(dir, p))
	})(result)

	sort.Slice(result, func(i, j int) bool {
		if result[i].name == result[j].name {
			return result[i].version < result[j].version
		}
		return result[i].name < result[j].name
	})

	return result, nil
}

func hasConflictingVersions(components []pythonDependency) bool {
	versions := make(map[string]string, len(components))
	for _, component := range components {
		name, version := component.name, component.version
		if version == "" {
			continue
		}
		if previous, ok := versions[name]; ok && previous != version {
			return true
		}
		versions[name] = version
	}
	return false
}

func hasRangeDeclarations(deps []pythonDependency) bool {
	for _, dep := range deps {
		if strings.ContainsAny(dep.declaration, "<>!~*,") {
			return true
		}
	}
	return false
}
