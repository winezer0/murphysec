package resolver

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

var ErrPythonUnavailable = errors.New("python 3 environment for dependency resolution is unavailable")
var ErrPipUnavailable = errors.New("pip command is unavailable")

var pythonCandidates = []string{
	"python3", "python3.14", "python3.13", "python3.12", "python3.11", "python3.10", "python3.9", "python",
}

// FindPython selects an available Python 3 executable from PATH.
func FindPython(ctx context.Context) (string, error) {
	for _, candidate := range pythonCandidates {
		path, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		if isPython3Executable(ctx, path) && supportsVirtualEnvironments(ctx, path) {
			return path, nil
		}
	}
	return "", fmt.Errorf("%w (looked for %s)", ErrPythonUnavailable, strings.Join(pythonCandidates, ", "))
}

func isPython3Executable(ctx context.Context, path string) bool {
	output, err := probePython(ctx, path, "--version")
	return err == nil && isPython3(output)
}

func supportsVirtualEnvironments(ctx context.Context, path string) bool {
	if _, err := probePython(ctx, path, "-m", "venv", "--help"); err != nil {
		return false
	}
	_, err := probePython(ctx, path, "-m", "ensurepip", "--version")
	return err == nil
}

func probePython(ctx context.Context, path string, args ...string) ([]byte, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return exec.CommandContext(probeCtx, path, args...).CombinedOutput()
}

func isPython3(output []byte) bool {
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Python 3.") {
			return true
		}
	}
	return false
}
