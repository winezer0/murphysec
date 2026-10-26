package npm

import (
	"encoding/json"
	"fmt"
	"sort"
)

type pkgFile struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Workspaces      []string          `json:"workspaces"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func (p pkgFile) DependenciesEntries() [][2]string {
	var r [][2]string
	for n, v := range p.Dependencies {
		r = append(r, [2]string{n, v})
	}
	sortEntries(r)
	return r
}

func (p pkgFile) DevDependenciesEntries() [][2]string {
	var r [][2]string
	for n, v := range p.DevDependencies {
		r = append(r, [2]string{n, v})
	}
	sortEntries(r)
	return r
}

func sortEntries(input [][2]string) {
	sort.Slice(input, func(i, j int) bool {
		if input[i][0] == input[j][0] {
			return input[i][1] < input[j][1]
		}
		return input[i][0] < input[j][0]
	})
}

func parsePkgFile(data []byte) (*pkgFile, error) {
	var e error
	var r pkgFile
	e = json.Unmarshal(data, &r)
	if e != nil {
		return nil, fmt.Errorf("parsing package file: bad format, %w", e)
	}
	return &r, nil
}

func packageFileFromLockfile(data []byte) (*pkgFile, error) {
	var lock struct {
		Name         string `json:"name"`
		Version      string `json:"version"`
		Dependencies map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"dependencies"`
		Packages map[string]struct {
			Name                 string            `json:"name"`
			Version              string            `json:"version"`
			Dependencies         map[string]string `json:"dependencies"`
			DevDependencies      map[string]string `json:"devDependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
			PeerDependencies     map[string]string `json:"peerDependencies"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parsing package-lock file: bad format, %w", err)
	}

	pkg := &pkgFile{
		Name:            lock.Name,
		Version:         lock.Version,
		Dependencies:    map[string]string{},
		DevDependencies: map[string]string{},
	}
	if root, ok := lock.Packages[""]; ok {
		if root.Name != "" {
			pkg.Name = root.Name
		}
		if root.Version != "" {
			pkg.Version = root.Version
		}
		for name, version := range root.Dependencies {
			pkg.Dependencies[name] = version
		}
		for name, version := range root.OptionalDependencies {
			pkg.Dependencies[name] = version
		}
		for name, version := range root.PeerDependencies {
			pkg.Dependencies[name] = version
		}
		for name, version := range root.DevDependencies {
			pkg.DevDependencies[name] = version
		}
	}
	if len(pkg.Dependencies)+len(pkg.DevDependencies) == 0 {
		for name, dep := range lock.Dependencies {
			if dep.Dev {
				pkg.DevDependencies[name] = dep.Version
			} else {
				pkg.Dependencies[name] = dep.Version
			}
		}
	}
	return pkg, nil
}
