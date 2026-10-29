package sessiontest

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoProductionFileImportsTheSessionDouble(t *testing.T) {
	const forbidden = `"github.com/anywaye/gateway/internal/sessiontest"`

	module, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("cannot resolve the module root: %v", err)
	}

	list := exec.CommandContext(context.Background(), "go", "list", "-deps", "./cmd/...")
	list.Dir = module
	out, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("`go list -deps ./cmd/...` failed, so this check cannot tell whether the binary links the session double: %v\n%s", err, out)
	}

	var packages int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		packages++
		if strings.HasSuffix(trimmed, "/internal/sessiontest") {
			t.Errorf("the binary links %s. The Go service ships no session store — `internal/session` records why — and linking a fixture is a per-process session store in the binary by another name.", trimmed)
		}
	}
	if packages < 5 {
		t.Fatalf("`go list -deps ./cmd/...` named %d package(s). The gateway binary links the standard library and three dependencies, so fewer than five means the module layout moved and this check has stopped checking anything", packages)
	}


	var scanned int
	err = filepath.WalkDir(filepath.Join(module, "cmd"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		scanned++

		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, relErr := filepath.Rel(module, path)
		if relErr != nil {
			relative = path
		}
		if strings.Contains(string(source), forbidden) {
			t.Errorf("%s imports %s. Everything under cmd/ is a program's front door, so this is shipped code whatever the import graph says today.", relative, forbidden)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking cmd/ failed: %v", err)
	}

	if scanned == 0 {
		t.Fatalf("no non-test .go file was found under cmd/, so the second half of this check proved nothing. Either the entry point moved or the walk is wrong, and both must be loud: a green that compared no files is worse than no check")
	}

	t.Logf("sessiontest: the binary links %d package(s), none of them this one; and none of the %d source file(s) under cmd/ names it", packages, scanned)
}
