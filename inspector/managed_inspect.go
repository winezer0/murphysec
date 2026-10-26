package inspector

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/murphysecurity/murphysec/infra/logctx"
	"github.com/murphysecurity/murphysec/model"
	"github.com/murphysecurity/murphysec/module"
	"github.com/murphysecurity/murphysec/scanerr"
	"github.com/murphysecurity/murphysec/utils"
	"go.uber.org/zap"
	"path/filepath"
	"time"
)

func setBasePath(ctx context.Context, path string) context.Context {
	return context.WithValue(ctx, model.BasePathKey, path)
}
func ManagedInspect(ctx context.Context) error {
	var logger = logctx.Use(ctx)
	scanTask := model.UseScanTask(ctx)

	// 获取扫描路径
	baseDir := scanTask.ProjectPath
	logger.Info("Auto scan dir", zap.String("dir", baseDir))

	// 扫
	var scanner = &dirScanner{
		inspectors: module.Inspectors,
		root:       baseDir,
	}
	scanner.scan(ctx)

	logger.Sugar().Infof("Found %d directories", len(scanner.scannedDirs))
	ctx = setBasePath(ctx, baseDir)
	// 对扫到的内容，逐个开始检查
	var inspectErrors []error
	for idx, it := range scanner.scannedDirs {
		st := time.Now()
		// 创建检查任务
		c := model.WithInspectionTask(ctx, scanTask.BuildInspectionTask(it.path))
		// 绑定 logger
		c = logctx.With(c, logger.Named(fmt.Sprintf("%s-%d", it.inspector.String(), idx)))

		// Do!
		logger.Sugar().Infof("Begin: %s", it.String())
		e := it.inspector.InspectProject(c)
		logger.Sugar().Infof("End: %s, duration: %v", it.String(), time.Since(st))
		if e != nil {
			logger.Error("InspectError", zap.Error(e), zap.Any("inspector", it))
			inspectErrors = append(inspectErrors, fmt.Errorf("%s at %s: %w", it.inspector.String(), it.path, e))
			scanerr.Add(ctx, scanerr.Param{
				Kind:    scanerr.KindInspectorFailed,
				Content: fmt.Sprintf("%s inspector failed for %s; dependency data may be incomplete", it.inspector.String(), filepath.Base(it.path)),
			})
		}
	}

	var components []model.Component
	for _, m := range scanTask.Modules {
		components = append(components, m.ComponentList()...)
	}
	logger.Sugar().Debugf("scan code fragments, total %d components", len(components))
	components = utils.DistinctSlice(components)
	previews, e := scanFragment(ctx, scanTask.ProjectPath, components)
	if e != nil {
		logger.Sugar().Errorf("errors during scan fragment: %s", e.Error())
	} else {
		scanTask.CodeFragments = previews
	}
	return errors.Join(inspectErrors...)
}
