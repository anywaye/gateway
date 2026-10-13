package httpapi

import (
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/cafaye/gateway/internal/api"
)

// This file holds the ROUTER to the DOCUMENT, in both directions.
//
// `test/openapiDocument.test.ts` does the same for the TypeScript implementation
// by reading `app.routes` — Hono's own table. There is no equivalent to read
// here, because the chi router this package builds is not the artifact anyone
// writes by hand: it is `internal/api/api.gen.go`, generated from
// `openapi/v1.yaml` by `oapi-codegen`. So the two sides of the comparison are
//
//	the router chi.Walk reports, and
//	the route registrations in the GENERATED file,
//
// and the generated file is the document's own routing table one translation
// removed. That is a weaker statement than the TypeScript test's and it is worth
// saying why rather than pretending otherwise: nothing here reads the YAML. What
// closes the gap is `bin/prime-go`'s regenerate-and-diff, which fails when
// `api.gen.go` and the document disagree — so the derived set below cannot go
// stale without a red gate, and a route can only leave this router when the
// document stops declaring it.
//
// # WHY THE REGISTRATIONS ARE PARSED RATHER THAN TRANSCRIBED
//
// A hand-written list of seven routes is a second inventory of the document, and
// it goes stale silently: an eighth operation lands in the document, the
// generated file grows a line, and the list still says seven. So it is read out
// of the file — by content, and with a pattern that fails rather than returning
// nothing, because a parser that finds no registrations and a document with none
// produce the same empty set.

// generatedFile is where the registrations are read from, relative to this
// package's directory.
const generatedFile = "../api/api.gen.go"

// registration matches the generator's route registrations.
//
// The `options.BaseURL+` prefix is absent from the pattern because
// `internal/api/stripbaseurl` removes it — and that is not cosmetic. The pattern
// deliberately requires the path literal to be the FIRST thing after `(`, which
// is the same requirement core's account-scope checker has, and the same reason:
// `r.Get(options.BaseURL+"/v1/me", …)` is the one shape of Go route registration
// that checker cannot read, and a parser that could not see a route would report
// the same count as a document with none.
var registration = regexp.MustCompile(`(?m)^\s*r\.(Get|Post|Put|Patch|Delete|Head)\("([^"]+)"`)

// route is one `(method, path)` pair on the router.
type route struct {
	method string
	path   string
}

func (r route) String() string { return r.method + " " + r.path }

// declaredRoutes reads the route registrations out of the generated file.
//
// Two failures are failures rather than empty sets, and the distinction is the
// whole reason this is a function and not an inline `regexp.FindAllString`:
//
//   - the file cannot be read, or
//   - it registers nothing.
//
// The second is the one that matters. A generator that changed how it spells a
// registration would leave this returning an empty list, every comparison below
// would pass vacuously, and the suite would be reporting that the router and the
// document agree because it could read neither.
func declaredRoutes(t *testing.T) []route {
	t.Helper()

	body, err := os.ReadFile(generatedFile)
	if err != nil {
		t.Fatalf("cannot read %s: %v", generatedFile, err)
	}

	var routes []route
	for _, match := range registration.FindAllStringSubmatch(string(body), -1) {
		routes = append(routes, route{method: strings.ToUpper(match[1]), path: match[2]})
	}

	if len(routes) == 0 {
		t.Fatalf("%s registers no routes and this pattern found none of them, so every comparison against it passes vacuously. Either the generator changed how it writes a registration, or this pattern is stale.", generatedFile)
	}

	sort.Slice(routes, func(i, j int) bool { return routes[i].String() < routes[j].String() })
	return routes
}

// servedRoutes reads the routes off the live router with `chi.Walk` — the thing
// `account_scope.yml` cannot do, and the reason `internal/httpapi` holds this
// contract rather than the manifest being a copy.
func servedRoutes(t *testing.T) []route {
	t.Helper()

	handler, err := New(Options{})
	if err != nil {
		t.Fatalf("New refused an empty configuration: %v", err)
	}

	router, ok := handler.(chi.Routes)
	if !ok {
		t.Fatalf("New returned a %T, which is not a chi.Routes and therefore cannot be walked. A check that cannot see the router is a check that passes without having looked.", handler)
	}

	var routes []route
	err = chi.Walk(router, func(method, routePattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, route{method: strings.ToUpper(method), path: routePattern})
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk failed: %v", err)
	}

	sort.Slice(routes, func(i, j int) bool { return routes[i].String() < routes[j].String() })
	return routes
}

// The router serves what the document declares, in both directions. A route on
// the router that the document does not declare is a gateway answering something
// nobody contracted for; a declaration the router does not serve is a document
// promising a 404 that is not what a client gets.
func TestTheRouterServesExactlyWhatTheGeneratedDocumentDeclares(t *testing.T) {
	declared := declaredRoutes(t)
	served := servedRoutes(t)

	declaredSet := map[string]bool{}
	for _, r := range declared {
		declaredSet[r.String()] = true
	}
	servedSet := map[string]bool{}
	for _, r := range served {
		servedSet[r.String()] = true
	}

	// `HEAD` is the deliberate exception, and it is removed from the SERVED set
	// rather than from the declared one: `New` registers the two `HEAD` routes
	// itself, the document declares neither, and every other difference is a
	// finding. `TestTheHeadRoutesAreTheProbePaths` is what holds the removed ones
	// to `ProbePaths`, so they are accounted for rather than excused.
	for name := range servedSet {
		if strings.HasPrefix(name, http.MethodHead+" ") {
			delete(servedSet, name)
		}
	}

	var extra, missing []string
	for name := range servedSet {
		if !declaredSet[name] {
			extra = append(extra, name)
		}
	}
	for _, r := range declared {
		if !servedSet[r.String()] {
			missing = append(missing, r.String())
		}
	}

	sort.Strings(extra)
	sort.Strings(missing)

	if len(extra) > 0 {
		t.Errorf("the router serves %v and the document declares none of them. A route nobody contracted for is a gateway answering something outside its contract.", extra)
	}
	if len(missing) > 0 {
		t.Errorf("the document declares %v and the router serves none of them. The document promises an answer the service will not give.", missing)
	}

	if len(declared) < 7 {
		t.Errorf("the generated file registers %d route(s); openapi/v1.yaml declares the contract's operations and the generator emits one registration each. Fewer means this file is not reading the document.", len(declared))
	}
}

// The `HEAD` registrations are exactly the probe paths, in both directions.
//
// This is the mechanism that makes `ProbePaths` a contract rather than a set
// somebody typed: a probe path added without its `HEAD` route is a path an
// orchestrator cannot ask about, and a `HEAD` route added without being a probe
// path is an operation the limiter's exemption set does not know about.
func TestTheHeadRoutesAreTheProbePaths(t *testing.T) {
	var heads []string
	for _, r := range servedRoutes(t) {
		if r.method == http.MethodHead {
			heads = append(heads, r.path)
		}
	}
	sort.Strings(heads)

	want := sortedKeys(ProbePaths)
	if strings.Join(heads, ",") != strings.Join(want, ",") {
		t.Errorf("the router answers HEAD on %v and ProbePaths says %v. A health checker asking with HEAD must reach the same operations the limiter is told to spare.", heads, want)
	}
}

// Every operation in the generated document is implemented by the `api.ServerInterface`
// this package provides. The generated code will not compile without the whole
// interface, so this is nearly tautological — and it is here anyway, named as
// the tripwire for the direction that matters: a NEW operation added to the
// document arrives as a method this package must implement, and a reader asking
// "what happens to it?" gets an answer from the compiler first and from
// `TestEveryOperationIsEitherServedOrDeclined` second.
func TestTheServerImplementsEveryOperationTheDocumentDeclares(t *testing.T) {
	var _ api.ServerInterface = (*server)(nil)

	// And the document's own count, so the two lists in
	// `TestEveryOperationIsEitherServedOrDeclined` are checked against the
	// generator rather than against a number typed into a test. Anything a new
	// operation adds appears in neither list and is named as undecided there.
	declared := declaredRoutes(t)
	if len(declared) != 10 {
		t.Errorf("the generated file registers %d operation(s); the two lists in TestEveryOperationIsEitherServedOrDeclined describe ten, so one of them is stale", len(declared))
	}
}
