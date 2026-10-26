package npm

import (
	"encoding/json"
	"fmt"
	"github.com/murphysecurity/murphysec/model"
	"github.com/murphysecurity/murphysec/utils"
	"sort"
	"strings"
)

type v3Lockfile struct {
	Name            string               `json:"name"`
	Version         string               `json:"version"`
	LockfileVersion int                  `json:"lockfileVersion"`
	Packages        map[string]v3Package `json:"packages"`
}

type v3Package struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Dev                  bool              `json:"dev"`
	Link                 bool              `json:"link"`
	Resolved             string            `json:"resolved"`
	PeerDependenciesMeta map[string]struct {
		Optional bool `json:"optional"`
	} `json:"peerDependenciesMeta"`
}

func processLockfileV3(data []byte) (r *model.DependencyItem, e error) {
	version, err := parseLockfileVersion(data)
	if err != nil {
		return nil, err
	}
	if version != 2 && version != 3 {
		return nil, fmt.Errorf("unsupported packages lockfile version: %d", version)
	}
	var lockfile v3Lockfile
	if e := json.Unmarshal(data, &lockfile); e != nil {
		return nil, fmt.Errorf("parse lockfile failed: %w", e)
	}
	if lockfile.Packages == nil {
		lockfile.Packages = make(map[string]v3Package)
	}
	var handler visitV3Handler[*model.DependencyItem] = func(theValue *model.DependencyItem, pred, succ [2]string, isDev bool, doNext func(nextValue *model.DependencyItem)) {
		var dep = model.DependencyItem{
			Component:          model.Component{CompName: succ[0], CompVersion: succ[1], EcoRepo: EcoRepo},
			DependencyRelation: model.DependencyRelationTransitive,
		}
		dep.IsOnline.SetOnline(!isDev)
		doNext(&dep)
		theValue.Dependencies = append(theValue.Dependencies, dep)
	}
	var rootNode model.DependencyItem
	_visitV3[*model.DependencyItem](&lockfile, nil, nil, make(map[string]struct{}), &rootNode, handler, make(map[string]struct{}))
	// The root importer does not contain dependencies declared by npm
	// workspace members. Include each workspace importer in the dependency
	// graph so a monorepo scan does not silently omit member dependencies.
	workspacePaths := make([]string, 0, len(lockfile.Packages))
	for packagePath := range lockfile.Packages {
		if packagePath == "" || strings.Contains("/"+packagePath+"/", "/node_modules/") {
			continue
		}
		workspacePaths = append(workspacePaths, packagePath)
	}
	sort.Strings(workspacePaths)
	for _, packagePath := range workspacePaths {
		workspace := lockfile.Packages[packagePath]
		segments := strings.Split(packagePath, "/")
		_visitV3[*model.DependencyItem](&lockfile, &workspace, segments, make(map[string]struct{}), &rootNode, handler, make(map[string]struct{}))
	}
	rootNode.CompName = lockfile.Name
	rootNode.CompVersion = lockfile.Version
	if rootNode.CompName == "" {
		rootNode.CompName = lockfile.Packages[""].Name
	}
	if rootNode.CompVersion == "" {
		rootNode.CompVersion = lockfile.Packages[""].Version
	}
	for i := range rootNode.Dependencies {
		rootNode.Dependencies[i].DependencyRelation = model.DependencyRelationDirect
	}
	return &rootNode, nil
}

type visitV3Handler[T any] func(theValue T, pred, succ [2]string, isDev bool, doNext func(nextValue T))

func _visitV3[T any](lockfile *v3Lockfile, pred *v3Package, rPath []string, pathVisited map[string]struct{}, theValue T, handler visitV3Handler[T], pruneSet map[string]struct{}) {
	if pred == nil {
		var root, ok = lockfile.Packages[""]
		if ok {
			pred = &root
		} else {
			return
		}
	}
	var predV = [2]string{pred.Name, pred.Version}
	var traversalDependencies = func(m map[string]string) {
		for succName := range m {
			var succPath, succSegments, succ, ok = findV3Package(lockfile.Packages, rPath, succName)
			if !ok {
				continue
			}
			if _, ok := pathVisited[succPath]; ok {
				continue
			}
			pathVisited[succPath] = struct{}{}
			var succV = [2]string{succ.Name, succ.Version}
			// Preserve alias dependency names (e.g. "string-width-cjs": "npm:string-width@^4.2.0").
			// If succName is empty, fall back to lockfile package name.
			if succName != "" {
				succV[0] = succName
			} else if succV[0] == "" {
				succV[0] = succName
			}
			var doNext = func(v T) { _visitV3(lockfile, &succ, succSegments, pathVisited, v, handler, pruneSet) }
			if pruneSet != nil {
				if _, ok := pruneSet[succPath]; ok {
					doNext = func(v T) {}
				}
				pruneSet[succPath] = struct{}{}
			}
			handler(theValue, predV, succV, succ.Dev, doNext)
			delete(pathVisited, succPath)
		}
	}
	traversalDependencies(pred.Dependencies)
	traversalDependencies(pred.OptionalDependencies)
	traversalDependencies(pred.PeerDependencies)
	traversalDependencies(pred.DevDependencies)
}

func findV3Package(packages map[string]v3Package, rPath []string, name string) (key string, segments []string, pkg v3Package, ok bool) {
	key, segments, pkg, ok = npmFindCorrectPair(packages, rPath, name)
	if ok && pkg.Link {
		key = pkg.Resolved
		pkg, ok = packages[key]
		segments = strings.Split(key, "/")
	}
	return
}

func npmFindCorrectPair[U any](m map[string]U, rp []string, name string) (key string, segments []string, value U, ok bool) {
	rp = utils.CopySlice(rp)
	for {
		segments = append(rp, "node_modules", name)
		key = strings.Join(segments, "/")
		value, ok = m[key]
		if ok {
			return
		}
		segments = append(rp, name)
		key = strings.Join(segments, "/")
		value, ok = m[key]
		if ok {
			return
		}
		if len(rp) == 0 {
			break
		}
		rp = rp[:len(rp)-1]
	}
	key = ""
	segments = nil
	return
}
