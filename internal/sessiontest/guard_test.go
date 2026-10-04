package sessiontest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The deferral, enforced.
//
// `internal/session` records why this package is a fixture rather than the
// service's session store, and a reason in a package comment is a promise. This
// is the check that makes it a property: the shipped binary does not link it, and
// nothing under `cmd/` names it.
//
// # HALF ONE: THE BINARY DOES NOT DEPEND ON IT
//
// `go list -deps ./cmd/...` is the property stated exactly — the set of packages
// the shipped binary links. If `internal/sessiontest` is in it, the process holds
// a per-process session store, which is the thing this packet refused to port.
//
// It is the IMPORT GRAPH and not a filename pattern, and that is the correction.
// The first version of this check banned the import string from every non-test
// `.go` file under `cmd/` and `internal/`, and it went red on
// `internal/equivalence/scenarios.go` — a file only ever imported by a `_test.go`,
// and not in the binary. The rule it enforced was "no test-support file may name
// this package", which is not the rule anybody wanted; the rule is "no SHIPPED code
// may name it". Two similar rules, one of them wrong, and the wrong one reads like
// a principle.
//
// DERIVED, so it covers the next thing on the day it lands: a new `cmd/` entry point
// is in `./cmd/...` without anybody editing this file.
//
// And it FAILS if `go list` cannot run. A check that cannot answer is not a check
// that passed — `bin/prime-go` keeps that rule for the same reason, and it applies
// here: the module cache is local and this runs offline, so a failure means the
// layout moved.
//
// # HALF TWO: `cmd/` ITSELF DOES NOT NAME IT
//
// Belt and braces for the one case `go list` cannot see — a file under `cmd/` that
// imports this package and is not reachable from any `main`: a second entry point
// somebody adds next month and forgets to wire up. Scoped to `cmd/`, which is the
// directory whose every file is a program's front door, and derived by walking the
// directory rather than from a list of names.
func TestNoProductionFileImportsTheSessionDouble(t *testing.T) {
	const forbidden = `"github.com/cafaye/gateway/internal/sessiontest"`

	module, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("cannot resolve the module root: %v", err)
	}

	// Half one: the import graph of the shipped binary.
	//
	// `Dir` is the module root and not this package's directory, because `go list`
	// resolves `./cmd/...` against the WORKING DIRECTORY and `go test` runs a
	// package's tests in that package's own directory. Omitting it made the command
	// fail with "directory not found" — which, per the rule above, correctly
	// failed the test rather than quietly skipping the check.
	list := exec.Command("go", "list", "-deps", "./cmd/...")
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

	// Half two: every file under `cmd/` that is not a test.

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
