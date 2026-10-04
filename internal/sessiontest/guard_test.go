package sessiontest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The deferral, enforced.
//
// `internal/session` records why this package is a fixture rather than the
// service's session store, and a reason in a package comment is a promise. This
// is the check that makes it a property: no file under `cmd/` or `internal/`
// that is NOT a test may import this package, so "the Go service ships no session
// store" is something a reader can verify by running one test rather than
// something a later packet could quietly break by adding one import.
//
// # SCOPE IS DERIVED, AND THE DERIVATION FAILS LOUDLY
//
// The scope is the two DIRECTORIES, walked — not a list of filenames typed here,
// and not a `--include='*_test.go'` pattern. Both of those were the wrong tool in
// this repository's own history: a filename pattern finds nothing in a package
// whose tests are named something else, and then reports "no session store" about
// a file it never opened. So this walks `cmd/` and `internal/` and decides by
// CONTENT: `.go`, and not `_test.go`.
//
// A walk that finds nothing is a FAILURE. A reader who renamed `cmd/` would
// otherwise get a green saying the service has no session store, when in fact
// this check had stopped looking.

// TestNoProductionFileImportsTheSessionDouble is the whole check.
func TestNoProductionFileImportsTheSessionDouble(t *testing.T) {
	module, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("cannot resolve the module root: %v", err)
	}

	const forbidden = `"github.com/cafaye/gateway/internal/sessiontest"`

	var scanned int
	for _, root := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(module, root), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			// This file is not read: it is a `_test.go`, and the walk above has
			// already excluded it. Skipping it explicitly would be belt and braces
			// for a condition that cannot be false here.
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
				t.Errorf("%s imports %s. The Go service ships no session store — `internal/session` records why — and the only implementations of it in this module are fixtures. A production import here is a per-process session store in the binary by another name.", relative, forbidden)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s failed: %v", root, err)
		}
	}

	if scanned == 0 {
		t.Fatalf("no non-test .go file was found under cmd/ and internal/, so this check proved nothing about what the service imports. Either the layout moved or the walk is wrong, and both must be loud: a green that compared no files is worse than no check")
	}

	t.Logf("sessiontest: scanned %d production source file(s) under cmd/ and internal/; none imports the session double", scanned)
}
