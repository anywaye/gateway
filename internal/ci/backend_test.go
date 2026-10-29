package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var knownBackends = map[string]bool{
	"github-actions": true,
	"instabox":       true,
}

func repoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed, so the repository root cannot be found")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readBackend(t *testing.T, path string) string {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v. The backend switch this file checks does not exist", path, err)
	}
	backend := strings.TrimSpace(string(raw))
	if backend == "" {
		t.Fatalf("ci/backend is empty. An unset switch is not the fallback; write %q for that",
			"github-actions")
	}
	if strings.Contains(backend, "\n") {
		t.Fatalf("ci/backend holds more than one line %q. The switch is one backend, chosen once", backend)
	}
	return backend
}

func TestTheBackendIsOneKitShips(t *testing.T) {
	backend := readBackend(t, filepath.Join(repoRoot(t), "ci", "backend"))
	if !knownBackends[backend] {
		t.Errorf("ci/backend names %q, which kit's backends/README.md does not ship. "+
			"A backend nothing runs is a pipeline nothing runs: adopt it in kit first, "+
			"then mirror it in knownBackends in the same commit.", backend)
	}
}

func TestBackendValidationRefusesWhatKitDoesNotShip(t *testing.T) {
	for _, backend := range []string{
		"",
		"github_actions",
		"GitHub-Actions",
		"actions",
		"sandbox",
		"localhost",
	} {
		trimmed := strings.TrimSpace(backend)
		if trimmed == "" || strings.Contains(trimmed, "\n") {
			continue
		}
		if knownBackends[backend] {
			t.Errorf("backend %q is accepted, so this table cannot prove refusal. "+
				"A negative control that passes is not a control.", backend)
		}
	}
	for _, backend := range []string{"github-actions", "instabox"} {
		if !knownBackends[backend] {
			t.Errorf("backend %q is refused, so a legal switch value fails the gate. "+
				"The allowlist drifted from kit's table.", backend)
		}
	}
}

func TestThePipelineIsShellSound(t *testing.T) {
	path := filepath.Join(repoRoot(t), "ci", "pipeline.sh")
	out, err := exec.CommandContext(t.Context(), "bash", "-n", path).CombinedOutput()
	if err != nil {
		t.Errorf("bash -n %s: %v\n%s. A pipeline with a syntax error gates nothing.", path, err, out)
	}
}

func TestThePipelineIsExecutable(t *testing.T) {
	path := filepath.Join(repoRoot(t), "ci", "pipeline.sh")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v. The pipeline this file checks does not exist", path, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Errorf("ci/pipeline.sh mode %s carries no executable bit. "+
			"The backend executes this file; commit it with `chmod +x`.", info.Mode())
	}
}
