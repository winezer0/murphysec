package inspector

import (
	"context"

	"github.com/murphysecurity/murphysec/internal/versionaudit"
	"github.com/murphysecurity/murphysec/model"
	"github.com/murphysecurity/murphysec/scanerr"
)

// expandEndpoints normalizes all inspector outputs before component collection.
func expandEndpoints(ctx context.Context, task *model.ScanTask) error {
	settings, err := (versionaudit.Settings{}).Environment()
	if err != nil {
		return err
	}
	directory, err := settings.Directory()
	if err != nil {
		return err
	}

	for i := range task.Modules {
		task.Modules[i].Dependencies = expandDependencies(ctx, task.Modules[i].Dependencies, directory, 0)
	}
	return ctx.Err()
}

// expandDependencies expands candidate leaves while preserving verified dependency trees.
func expandDependencies(ctx context.Context, deps []model.DependencyItem, directory versionaudit.Directory, depth int) []model.DependencyItem {
	if depth > 256 {
		scanerr.Add(ctx, scanerr.Param{Kind: "version_audit_graph_limit", Content: "dependency graph exceeds endpoint expansion depth limit"})
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	var result []model.DependencyItem
	for _, dep := range deps {
		declaration := dep.DeclaredVersion
		if declaration == "" && versionaudit.IsConstraint(dep.CompVersion) {
			declaration = dep.CompVersion
		}
		if declaration == "" {
			if dep.VersionSource == "" {
				dep.VersionSource = string(versionaudit.Actual)
				if dep.CompVersion == "" {
					dep.VersionSource = "unresolved"
				}
			}
			dep.Dependencies = expandDependencies(ctx, dep.Dependencies, directory, depth+1)
			result = append(result, dep)
			continue
		}
		candidates, err := versionaudit.ResolveDeclaration(ctx, versionaudit.Declaration{Ecosystem: dep.Ecosystem, Name: dep.CompName, Constraint: declaration}, directory)
		if err != nil || len(candidates.Candidates) == 0 {
			dep.CompVersion, dep.VersionSource = "", "unresolved"
			dep.Dependencies = nil
			result = append(result, dep)
			scanerr.Add(ctx, scanerr.Param{Kind: "version_audit_unresolved", Content: "version audit unresolved for " + dep.CompName})
			continue
		}
		for _, candidate := range candidates.Candidates {
			item := dep
			item.CompVersion, item.VersionSource = candidate.Version, string(candidate.Source)
			if candidate.Source == versionaudit.DeclaredExact {
				item.Dependencies = expandDependencies(ctx, dep.Dependencies, directory, depth+1)
			} else {
				item.Dependencies = nil
			}
			result = append(result, item)
		}
	}
	return result
}
