package httpapi

import (
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/anywaye/gateway/internal/api"
)


const generatedFile = "../api/api.gen.go"

var registration = regexp.MustCompile(`(?m)^\s*r\.(Get|Post|Put|Patch|Delete|Head)\("([^"]+)"`)

type route struct {
	method string
	path   string
}

func (r route) String() string { return r.method + " " + r.path }

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

func TestTheServerImplementsEveryOperationTheDocumentDeclares(t *testing.T) {
	var _ api.ServerInterface = (*server)(nil)

	declared := declaredRoutes(t)
	if len(declared) != 10 {
		t.Errorf("the generated file registers %d operation(s); the two lists in TestEveryOperationIsEitherServedOrDeclined describe ten, so one of them is stale", len(declared))
	}
}
