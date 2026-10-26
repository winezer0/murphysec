package npm

import (
	"encoding/json"
	"fmt"
	"strings"
)

func parseLockfileVersion(data []byte) (int, error) {
	type legacyPackage struct {
		Version      string                    `json:"version"`
		Dependencies map[string]*legacyPackage `json:"dependencies"`
	}
	var u struct {
		LockfileVersion int                       `json:"lockfileVersion"`
		Name            string                    `json:"name"`
		Version         string                    `json:"version"`
		Dependencies    map[string]*legacyPackage `json:"dependencies"`
		Packages        map[string]*v3Package     `json:"packages"`
	}
	if e := json.Unmarshal(data, &u); e != nil {
		return 0, fmt.Errorf("parsing lockfile version: %w", e)
	}
	if u.LockfileVersion < 1 || u.LockfileVersion > 3 {
		return 0, fmt.Errorf("unsupported lockfileVersion %d (supported: 1, 2, 3)", u.LockfileVersion)
	}
	if u.LockfileVersion == 1 {
		var top map[string]json.RawMessage
		_ = json.Unmarshal(data, &top)
		if strings.TrimSpace(string(top["dependencies"])) == "null" {
			return 0, fmt.Errorf("dependencies must be an object, not null")
		}
		if u.Dependencies == nil && u.Name == "" && u.Version == "" {
			return 0, fmt.Errorf("missing dependencies or project metadata")
		}
		var validate func(map[string]*legacyPackage) error
		validate = func(deps map[string]*legacyPackage) error {
			for name, dep := range deps {
				if dep == nil || dep.Version == "" {
					return fmt.Errorf("invalid dependency %q: missing package or version", name)
				}
				if err := validate(dep.Dependencies); err != nil {
					return err
				}
			}
			return nil
		}
		return u.LockfileVersion, validate(u.Dependencies)
	}
	if u.Packages[""] == nil {
		return 0, fmt.Errorf("missing packages[\"\"] root entry")
	}
	packages := make(map[string]v3Package, len(u.Packages))
	for packagePath, pkg := range u.Packages {
		if pkg == nil {
			return 0, fmt.Errorf("null package entry %q", packagePath)
		}
		packages[packagePath] = *pkg
	}
	for packagePath, pkg := range packages {
		if pkg.Link {
			target, ok := packages[pkg.Resolved]
			if pkg.Resolved == "" || !ok || target.Link {
				return 0, fmt.Errorf("invalid link %q -> %q", packagePath, pkg.Resolved)
			}
			continue
		}
		if strings.Contains("/"+packagePath+"/", "/node_modules/") && pkg.Version == "" {
			return 0, fmt.Errorf("missing version for %q", packagePath)
		}
		for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.PeerDependencies} {
			for name := range deps {
				if _, optional := pkg.OptionalDependencies[name]; optional || pkg.PeerDependenciesMeta[name].Optional {
					continue
				}
				if _, _, _, ok := findV3Package(packages, strings.Split(packagePath, "/"), name); !ok {
					return 0, fmt.Errorf("unresolved dependency %q in %q", name, packagePath)
				}
			}
		}
	}
	return u.LockfileVersion, nil
}
