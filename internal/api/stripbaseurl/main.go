package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	generated = "api.gen.go"

	token = "options.BaseURL+"
	drop  = ""

	note = `// POST-PROCESSED BY internal/api/stripbaseurl, run by the second //go:generate
// line above. The route registrations below read ` + "`" + `r.Get("/healthz", …)` + "`" + ` rather
// than the generator's ` + "`" + `r.Get(options.BaseURL+"/healthz", …)` + "`" + ` so that
// core's account-scope checker can read them; see that command's own header. The
// token and ` + "`" + `options.BaseURL` + "`" + ` default to ` + "`" + `/` + "`" + ` when a caller leaves them
// empty, so the routes are the same routes. Regeneration rewrites the change, and
// this step puts it back.
`
)

func main() {
	source, err := os.ReadFile(generated)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stripbaseurl: cannot read %s: %v\n", generated, err)
		os.Exit(1)
	}

	rewritten := strings.ReplaceAll(string(source), token, drop)
	count := strings.Count(string(source), token)
	if count == 0 {
		fmt.Fprintf(os.Stderr,
			"stripbaseurl: %s contains no %q, so this command achieved nothing and the\n"+
				"  routes in it are still invisible to core's account-scope checker. Either the\n"+
				"  generator changed how it spells the base URL, or this command is no longer\n"+
				"  the right place to remove it. Do not delete this step to make the gate green:\n"+
				"  find out which of the two it is first.\n", generated, token)
		os.Exit(1)
	}

	if strings.Contains(rewritten, token) {
		fmt.Fprintf(os.Stderr, "stripbaseurl: %s still contains %q after rewriting it.\n", generated, token)
		os.Exit(1)
	}

	if !strings.HasPrefix(rewritten, "// POST-PROCESSED BY") {
		rewritten = note + rewritten
	}

	if err := os.WriteFile(generated, []byte(rewritten), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "stripbaseurl: cannot write %s: %v\n", generated, err)
		os.Exit(1)
	}

	fmt.Printf("stripbaseurl: rewrote %d route registration(s) in %s\n", count, generated)
}
