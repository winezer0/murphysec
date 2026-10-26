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
	var goModPath = filepath.Join(task.Dir(), "go.mod")
	// modules.txt 只说明「谁被 require」，不区分直接 import 和间接需要，
	// 所以直接/间接回到 go.mod 的 `// indirect` 注释上判断。
	var relations = goModRelations(goModPath)
	var directs, indirects = make([]model.DependencyItem, 0, len(mods)), make([]model.DependencyItem, 0)
	for _, m := range mods {
		var direct bool
		if relations == nil {
			// 没有 go.mod 可参考（只有 vendor 目录）时，explicit 是唯一线索。
			direct = m.Explicit
		} else {
			// replace 改了路径的模块在 go.mod 里查不到，按间接处理比错标直接安全。
			direct = relations[m.Path]
		}
		var item = model.DependencyItem{
			Component: model.Component{
				CompName:    m.Path,
				CompVersion: m.Version,
				EcoRepo:     EcoRepo,
			},
			IsOnline: model.IsOnline{Value: true, Valid: true},
		}
		if direct {
			item.DependencyRelation = model.DependencyRelationDirect
			directs = append(directs, item)
		} else {
			item.DependencyRelation = model.DependencyRelationTransitive
			indirects = append(indirects, item)
		}
	}
	var modName, _ = getModInfo(goModPath)
	if modName == "" {
		modName = filepath.Base(task.Dir())
	}
	task.AddModule(model.Module{
		PackageManager: "gomod",
		ModulePath:     goModPath,
		ModuleName:     modName,
		Dependencies:   buildModuleGraph(modName, directs, indirects),
	})
}

// buildModuleGraph 把平铺的依赖组装成一个模块的依赖项。
//
// 静态解析只分得出「直接 require」和「间接」两档，拿不到完整的「谁依赖谁」。
// 但一个空的 relationships 会让 SBOM 消费者把整份清单看成互不相关的包，所以
// 至少把主模块作为根、把直接依赖挂在下面。间接依赖仍保持平铺：它们的父节点
// 确实未知，硬挂到根上等于宣称「主模块直接依赖它们」，是假数据。
func buildModuleGraph(rootName string, directs, indirects []model.DependencyItem) []model.DependencyItem {
	var out = make([]model.DependencyItem, 0, 1+len(indirects))
	out = append(out, model.DependencyItem{
		Component: model.Component{
			CompName: rootName,
			EcoRepo:  EcoRepo,
		},
		Dependencies:       directs,
		DependencyRelation: model.DependencyRelationDirect,
	})
	return append(out, indirects...)
}

var _ErrGoNotFound = errors.New("go not found")
