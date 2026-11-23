package resolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/murphysecurity/murphysec/infra/logctx"
	"go.uber.org/zap"
)

var hostPipOnce sync.Once
var hostPipPackages map[string]string
var hostPipError error

// HostPackageVersions reads installed versions from the host pip environment.
// Callers must decide whether host environment data is appropriate for a scan.
func HostPackageVersions(ctx context.Context) (map[string]string, error) {
	hostPipOnce.Do(func() {
		hostPipPackages, hostPipError = evalPipList(ctx)
	})
	return hostPipPackages, hostPipError
}

func evalPipList(ctx context.Context) (map[string]string, error) {
	const timeout = 15 * time.Second
	pip, err := selectPip(ctx)
	if err != nil {
		return nil, err
	}
	packages, err := evalPipListFormat(ctx, pip, timeout, "json")
	if err == nil {
		return packages, nil
	}
	return evalPipListFormat(ctx, pip, timeout, "")
}

func selectPip(ctx context.Context) (string, error) {
	for _, candidate := range []string{"pip3", "pip"} {
		if path, err := exec.LookPath(candidate); err == nil && path != "" {
			logctx.Use(ctx).Sugar().Infof("%s found: %s", candidate, path)
			return path, nil
		}
	}
	return "", ErrPipUnavailable
}

func evalPipListFormat(ctx context.Context, pip string, timeout time.Duration, format string) (map[string]string, error) {
	args := []string{"list", "--disable-pip-version-check", "--no-index"}
	if format != "" {
		args = append(args, "--format", format)
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, pip, args...)
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			logExitError(logctx.Use(ctx).Sugar(), exitErr)
		}
		return nil, fmt.Errorf("eval pip list failed: %w", err)
	}
	if format == "json" {
		return parsePipListJSON(output)
	}
	return parsePipListDefault(output)
}

var pipListDefaultPattern = regexp.MustCompile(`^([\w_-]+)\s\(([\w.-]+)\)$`)

func parsePipListDefault(data []byte) (map[string]string, error) {
	result := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		match := pipListDefaultPattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) == 0 {
			continue
		}
		result[match[1]] = match[2]
	}
	return result, nil
}

func parsePipListJSON(data []byte) (map[string]string, error) {
	var packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &packages); err != nil {
		return nil, err
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].Name < packages[j].Name
	})
	result := make(map[string]string, len(packages))
	for _, item := range packages {
		if item.Version != "" {
			result[item.Name] = item.Version
		}
	}
	return result, nil
}

func logExitError(logger *zap.SugaredLogger, err *exec.ExitError) {
	logger.Warnf("pip list exited with code %d", err.ExitCode())
	for _, line := range strings.Split(string(err.Stderr), "\n") {
		if strings.TrimSpace(line) != "" {
			logger.Debugf("pip list output: %s", line)
		}
	}
}
