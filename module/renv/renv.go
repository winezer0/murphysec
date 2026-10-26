package renv

import (
	"context"
	"fmt"
	"github.com/murphysecurity/murphysec/infra/logctx"
	"github.com/murphysecurity/murphysec/model"
	"github.com/murphysecurity/murphysec/utils"
	"github.com/murphysecurity/murphysec/utils/simplejson"
	"os"
	"path/filepath"
)

type Inspector struct{}

func (Inspector) String() string {
	return "REnv"
}

func (Inspector) CheckDir(ctx context.Context, dir string) bool {
	return utils.IsFile(filepath.Join(dir, "renv.lock"))
}

func (Inspector) InspectProject(ctx context.Context) error {
	inspectTask := model.UseInspectionTask(ctx)
	logger := logctx.Use(ctx)
	data, e := os.ReadFile(filepath.Join(inspectTask.Dir(), "renv.lock"))
	if e != nil {
		return fmt.Errorf("read renv.lock: %w", e)
	}
	j, e := simplejson.NewJSON(data)
	if e != nil || j == nil {
		return fmt.Errorf("parse renv.lock: %w", e)
	}
	var deps []model.DependencyItem
	for _, it := range j.Get("Packages").JSONMap() {
		if it == nil {
			continue
		}
		var name = it.Get("Package").String()
		var version = it.Get("Version").String()
		var di model.DependencyItem
		di.CompName = name
		di.CompVersion = version
		di.EcoRepo = EcoRepo
		deps = append(deps, di)
	}
	if len(deps) == 0 {
		logger.Warn("No valid package item found")
		return nil
	}
	inspectTask.AddModule(model.Module{
		PackageManager: "renv",
		ModuleName:     "RProject",
		ModulePath:     filepath.Join(inspectTask.Dir(), "renv.lock"),
		Dependencies:   deps,
	})
	return nil
}

func (Inspector) SupportFeature(feature model.InspectorFeature) bool {
	return false
}

// EcoRepo identifies the ecosystem renv packages belong to. renv manages R
// libraries and installs them from CRAN, so the ecosystem is "cran".
//
// This used to say "spm" (Swift Package Manager), which meant two things went
// wrong at once: no purl could be generated (spm was not in the purl table),
// and any purl that had been generated would have pointed OSV at the Swift
// vulnerability database. R projects were reported with no vulnerabilities at
// all because the packages were dropped as unidentifiable.
var EcoRepo = model.EcoRepo{
	Ecosystem:  "cran",
	Repository: "",
}
