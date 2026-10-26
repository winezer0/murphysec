package scan

import "github.com/murphysecurity/murphysec/model"

// SBOM output filters.
//
// They exist because the dependency graph murphysec builds is the full
// declared graph, while an SBOM is usually consumed to answer "what ships".
// Keeping the filtering here rather than in a downstream converter means the
// emitted document is already the one the scanner should act on.

// excludeDevDeps drops dependencies flagged as dev-only: test, provided and
// system scope in Maven, dev dependencies in npm and so on.
var excludeDevDeps bool

// directOnlyDeps keeps only the dependencies the project itself declares.
var directOnlyDeps bool

// filterModulesForSBOM applies the requested output filters in place.
func filterModulesForSBOM(modules []model.Module) {
	if !excludeDevDeps && !directOnlyDeps {
		return
	}
	for i := range modules {
		modules[i].Dependencies = filterDependencyItems(modules[i].Dependencies)
	}
}

func filterDependencyItems(in []model.DependencyItem) []model.DependencyItem {
	if len(in) == 0 {
		return in
	}
	out := in[:0]
	for _, dep := range in {
		// IsOnline has a Valid flag: when it was never set the dependency is
		// treated as shipping, matching the marshalling default of true.
		if excludeDevDeps && dep.IsOnline.Valid && !dep.IsOnline.Value {
			continue
		}
		if directOnlyDeps && dep.DependencyRelation != model.DependencyRelationDirect {
			continue
		}
		dep.Dependencies = filterDependencyItems(dep.Dependencies)
		out = append(out, dep)
	}
	return out
}
