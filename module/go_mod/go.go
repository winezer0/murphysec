package go_mod

import (
	"context"
	"path/filepath"

	"github.com/murphysecurity/murphysec/infra/ui"
	"github.com/murphysecurity/murphysec/model"
	"github.com/murphysecurity/murphysec/utils"
	"github.com/pkg/errors"
)

type Inspector struct{}

func (Inspector) SupportFeature(feature model.InspectorFeature) bool {
	return model.InspectorFeatureAllowNested&feature > 0
}

func (Inspector) String() string {
	return "GoMod"
}

func (Inspector) CheckDir(ctx context.Context, dir string) bool {
	return utils.IsFile(filepath.Join(dir, "go.mod")) || utils.IsFile(filepath.Join(dir, "Gopkg.lock"))
}

func (Inspector) InspectProject(ctx context.Context) error {
	task := model.UseInspectionTask(ctx)
	// vendor 构建下 vendor/modules.txt 才是本次编译实际使用的模块集合：go 命令
	// 已经把 replace、MVS 和 exclude 算完，还标出哪些模块被主模块直接 require。
	// 只读 go.mod 拿到的是输入而不是结果，两者在 replace 过的项目上版本会不同。
	// 这条路径也不依赖 go 命令，内网工程可以照常离线使用。
	if mods, ok := readVendorModules(filepath.Join(task.Dir(), "vendor", "modules.txt")); ok {
		addVendorModule(ctx, mods)
		return nil
	}
	if utils.IsFile(filepath.Join(task.Dir(), "go.mod")) {
		// 新版本
		if task.IsNoBuild() {
			ui.Use(ctx).Display(ui.MsgWarn, "通过 go build获取依赖信息失败，可能会导致检测结果不完整或失败，访问 https://murphysec.com/docs/faqs/quick-start-for-beginners/programming-language-supported.html 了解详情")

			if err := baseScan(ctx); err != nil {
				return err
			}
		} else {
			if err := buildScan(ctx); err != nil {
				ui.Use(ctx).Display(ui.MsgWarn, "通过 go build获取依赖信息失败，可能会导致检测结果不完整或失败，访问 https://murphysec.com/docs/faqs/quick-start-for-beginners/programming-language-supported.html 了解详情")
				if err := baseScan(ctx); err != nil {
					return err
				}
			}
		}
	} else {
		// 旧版本Gopkg
		if err := parserGoPkgLock(ctx); err != nil {
			return nil
		}
	}

	return nil
}

var EcoRepo = model.EcoRepo{
	Ecosystem:  "go",
	Repository: "",
}

// addVendorModule 把 vendor/modules.txt 的模块列表登记成一个 gomod 模块。
//
// 所有模块在这里都是平铺的：modules.txt 不记录「谁依赖谁」，只记录最终选中的
// 集合和「谁被主模块直接 require」。依赖关系因此只能分辨直接/间接，粒度与
// baseScan 读 go.mod 时一致，但版本更准确。
func addVendorModule(ctx context.Context, mods []vendorModule) {
	task := model.UseInspectionTask(ctx)
	var deps = make([]model.DependencyItem, 0, len(mods))
	for _, m := range mods {
		var relation = model.DependencyRelationTransitive
		if m.Explicit {
			relation = model.DependencyRelationDirect
		}
		deps = append(deps, model.DependencyItem{
			Component: model.Component{
				CompName:    m.Path,
				CompVersion: m.Version,
				EcoRepo:     EcoRepo,
			},
			DependencyRelation: relation,
			IsOnline:           model.IsOnline{Value: true, Valid: true},
		})
	}
	var modName, _ = getModInfo(filepath.Join(task.Dir(), "go.mod"))
	if modName == "" {
		modName = filepath.Base(task.Dir())
	}
	task.AddModule(model.Module{
		PackageManager: "gomod",
		ModulePath:     filepath.Join(task.Dir(), "go.mod"),
		ModuleName:     modName,
		Dependencies:   deps,
	})
}

var _ErrGoNotFound = errors.New("go not found")
