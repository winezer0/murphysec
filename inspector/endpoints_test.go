package inspector

import (
	"context"
	"testing"

	"github.com/murphysecurity/murphysec/model"
	"github.com/murphysecurity/murphysec/scanerr"
	"github.com/winezer0/opensca/versionaudit"
)

type endpointCatalog struct{ versions []string }

// Versions provides a deterministic catalog to the graph adapter.
func (c endpointCatalog) Versions(context.Context, versionaudit.Package) ([]string, error) {
	return c.versions, nil
}

// TestExpandDependenciesPreservesEvidence checks all supported declaration ecosystems.
func TestExpandDependenciesPreservesEvidence(t *testing.T) {
	for _, eco := range []string{"npm", "pypi", "composer", "bundler", "nuget", "maven"} {
		t.Run(eco, func(t *testing.T) {
			raw := ">1.0 <2.0"
			if eco == "pypi" || eco == "bundler" {
				raw = ">1.0,<2.0"
			}
			if eco == "nuget" || eco == "maven" {
				raw = "(1.0,2.0)"
			}
			dep := model.DependencyItem{Component: model.Component{CompName: "example", CompVersion: raw, DeclaredVersion: raw, EcoRepo: model.EcoRepo{Ecosystem: eco}}, DependencyRelation: model.DependencyRelationDirect, Dependencies: []model.DependencyItem{{Component: model.Component{CompName: "unverified", CompVersion: "9.0"}}}}
			got := expandDependencies(scanerr.WithCtx(context.Background()), []model.DependencyItem{dep}, endpointCatalog{[]string{"1.0", "1.1", "1.9", "2.0"}}, 0)
			if len(got) != 2 || got[0].CompVersion != "1.1" || got[1].CompVersion != "1.9" {
				t.Fatalf("candidates=%#v", got)
			}
			for _, item := range got {
				if item.DeclaredVersion != raw || item.VersionSource != "published_endpoint" || len(item.Dependencies) != 0 || item.DependencyRelation != dep.DependencyRelation {
					t.Fatalf("candidate=%#v", item)
				}
			}
		})
	}
}

// TestExpandDependenciesRetainsUnresolvedAndActual verifies preservation and provenance.
func TestExpandDependenciesRetainsUnresolvedAndActual(t *testing.T) {
	ctx := scanerr.WithCtx(context.Background())
	deps := []model.DependencyItem{{Component: model.Component{CompName: "pinned", CompVersion: "1.5", EcoRepo: model.EcoRepo{Ecosystem: "pypi"}}, Dependencies: []model.DependencyItem{{Component: model.Component{CompName: "child", CompVersion: "1.0"}}}}, {Component: model.Component{CompName: "unknown", DeclaredVersion: "!=1.0", EcoRepo: model.EcoRepo{Ecosystem: "pypi"}}}}
	got := expandDependencies(ctx, deps, endpointCatalog{}, 0)
	if len(got) != 2 || got[0].VersionSource != "actual" || len(got[0].Dependencies) != 1 || got[1].VersionSource != "unresolved" || got[1].CompVersion != "" {
		t.Fatalf("dependencies=%#v", got)
	}
	if len(scanerr.GetAll(ctx)) != 1 {
		t.Fatal("missing unresolved diagnostic")
	}
}
