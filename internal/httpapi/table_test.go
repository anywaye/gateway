package httpapi

import (
	"errors"
	"strings"
	"testing"
)



func TestABadRouteTableIsARefusalToConstructTheGateway(t *testing.T) {
	cases := []struct {
		name   string
		table  RouteTable
		absent string
	}{
		{
			name:   "an empty table forwards nothing and would never say so",
			table:  RouteTable{},
			absent: "at least one prefix",
		},
		{
			name:   "a relative prefix could never match the mount",
			table:  RouteTable{"v1/pantry": {BaseURL: "http://pantry:8080"}},
			absent: "absolute paths",
		},
		{
			name:   "a glob is a second matching language",
			table:  RouteTable{"/v1/*": {BaseURL: "http://pantry:8080"}},
			absent: "not patterns",
		},
		{
			name:   "a prefix outside the API surface",
			table:  RouteTable{"/auth/me": {BaseURL: "http://identity:8080"}},
			absent: "must live under",
		},
		{
			name:   "a prefix that is gateway's own route",
			table:  RouteTable{gatewayOwned: {BaseURL: "http://pantry:8080"}},
			absent: "gateway's own route",
		},
		{
			name:   "a prefix carrying an encoded traversal",
			table:  RouteTable{"/v1/%2e%2e/secret": {BaseURL: "http://pantry:8080"}},
			absent: "traversal segment",
		},
		{
			name:   "a base URL with a path in it",
			table:  RouteTable{"/v1/pantry": {BaseURL: "http://pantry:8080/api"}},
			absent: "no path",
		},
		{
			name:   "a base URL carrying a password",
			table:  RouteTable{"/v1/pantry": {BaseURL: "http://user:hunter2@pantry:8080"}},
			absent: "must not carry credentials",
		},
		{
			name:   "a token with a newline in it is header injection configured on purpose",
			table:  RouteTable{"/v1/pantry": {BaseURL: "http://pantry:8080", Token: "abc\r\nX-Injected: 1"}},
			absent: "whitespace or control characters",
		},
		{
			name:   "a public entry that also carries a service credential",
			table:  RouteTable{"/v1/catalog": {BaseURL: "http://pantry:8080", Token: "svc", Public: true}},
			absent: "declared public AND carries an upstream token",
		},
		{
			name:   "MD19: a public entry that also declares claims",
			table:  RouteTable{"/v1/catalog": {BaseURL: "http://pantry:8080", Public: true, Principal: []string{"sub"}}},
			absent: "declared public AND declares principal claims",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler, err := New(Options{Routes: tc.table})

			if err == nil {
				t.Fatalf("New accepted %+v, and the gateway would boot and forward nothing to a service that exists", tc.table)
			}
			if handler != nil {
				t.Error("New returned a handler as well as an error; a refusal to serve must not hand back something servable")
			}
			if !errors.Is(err, ErrNotConfigured) {
				t.Errorf("err is %v, which is not ErrNotConfigured — a caller cannot tell its own mistake from a defect", err)
			}
			if !strings.Contains(err.Error(), tc.absent) {
				t.Errorf("the refusal does not mention %q, so an operator reading it cannot tell which of the rules they broke:\n  %v", tc.absent, err)
			}
		})
	}
}

func TestTheJSONASpellingAnOperatorGetsWrongIsAlsoARefusal(t *testing.T) {
	cases := []struct {
		document string
		absent   string
	}{
		{document: `{"/v1/catalog":{"baseUrl":"http://pantry:8080","public":"true"}}`, absent: "must be true or false"},
		{document: `{"/v1/catalog":{"baseUrl":"http://pantry:8080","public":1}}`, absent: "must be true or false"},
		{document: `{"/v1/pantry":{"baseUrl":"http://pantry:8080","principal":"sub"}}`, absent: "array of claim names"},
		{document: `{"/v1/pantry":{"baseUrl":"http://pantry:8080","principal":[]}}`, absent: "empty array"},
		{document: `{"/v1/pantry":{"baseUrl":"http://pantry:8080","principal":["*"]}}`, absent: `may not name "*"`},
		{document: `{"/v1/pantry":{"baseUrl":"http://pantry:8080","principal":["iss"]}}`, absent: "gateway's own"},
		{document: `{"/v1/pantry":{"baseUrl":"http://pantry:8080","token":""}}`, absent: "non-empty string"},
		{document: `["/v1/pantry"]`, absent: "must be a JSON object"},
		{document: `not json at all`, absent: "must be a JSON object"},
	}

	for _, tc := range cases {
		t.Run(tc.document, func(t *testing.T) {
			table, err := ParseRouteTable(tc.document)

			if err == nil {
				t.Fatalf("ParseRouteTable accepted %s and returned %+v, so a misspelled security field resolved to something", tc.document, table)
			}
			if !errors.Is(err, ErrNotConfigured) {
				t.Errorf("err is %v, which is not ErrNotConfigured", err)
			}
			if !strings.Contains(err.Error(), tc.absent) {
				t.Errorf("the refusal does not mention %q:\n  %v", tc.absent, err)
			}
		})
	}
}

func TestAValidRouteTableIsNotRefused(t *testing.T) {
	document := `{
		"/v1/pantry":        {"baseUrl":"http://pantry:8080"},
		"/v1/pantry/import": {"baseUrl":"http://pantry:8080","token":"svc","principal":["sub","github_id"]},
		"/v1/catalog":       {"baseUrl":"https://pantry:8443","public":true},
		"/v1/pantry/admin":  {"baseUrl":"http://admin:9000/","public":false}
	}`

	table, err := ParseRouteTable(document)
	if err != nil {
		t.Fatalf("ParseRouteTable refused a valid table: %v", err)
	}
	if len(table) != 4 {
		t.Fatalf("the table has %d entries, want 4", len(table))
	}
	if got := table["/v1/pantry/import"].Principal; len(got) != 2 || got[0] != "sub" || got[1] != "github_id" {
		t.Errorf("the declared claims are %v, want [sub github_id] in the order the operator wrote them", got)
	}
	if got := table["/v1/catalog"].BaseURL; got != "https://pantry:8443" {
		t.Errorf("base URL is %q, want https://pantry:8443", got)
	}
	if got := table["/v1/pantry/admin"].BaseURL; got != "http://admin:9000" {
		t.Errorf("a trailing slash gave %q, want http://admin:9000 — it would join into //v1/…", got)
	}

	if _, err := New(Options{Routes: table}); err != nil {
		t.Errorf("New refused a table ParseRouteTable produced: %v", err)
	}
}

func TestAValidatedTableIsACopyTheCallerCannotReachInto(t *testing.T) {
	declared := []string{"sub"}
	table := RouteTable{"/v1/pantry": {BaseURL: "http://pantry:8080", Principal: declared}}

	checked, err := ValidateRouteTable(table)
	if err != nil {
		t.Fatalf("ValidateRouteTable refused a valid table: %v", err)
	}

	declared[0] = "github_id"
	if got := checked["/v1/pantry"].Principal; len(got) != 1 || got[0] != "sub" {
		t.Errorf("the validated table now reads %v; ValidateRouteTable must copy the declared claims", got)
	}

	checked["/v1/pantry"] = RouteTarget{BaseURL: "http://elsewhere:1"}
	if got := table["/v1/pantry"].BaseURL; got != "http://pantry:8080" {
		t.Errorf("the caller's map now points at %q; ValidateRouteTable must return a fresh one", got)
	}
}


func TestUpstreamPathRebuildsEverySegmentAndRefusesWhatItCannotExpress(t *testing.T) {
	cases := []struct {
		prefix string
		path   string
		want   string
		ok     bool
	}{
		{prefix: "/v1/pantry", path: "/v1/pantry", want: "/", ok: true},
		{prefix: "/v1/pantry", path: "/v1/pantry/", want: "/", ok: true},
		{prefix: "/v1/pantry", path: "/v1/pantry/items", want: "/items", ok: true},
		{prefix: "/v1/pantry", path: "/v1/pantry/items/", want: "/items", ok: true},
		{prefix: "/v1/pantry", path: "/v1/pantry/a/b/c", want: "/a/b/c", ok: true},

		{prefix: "/v1/pantry", path: "/v1/pantry/../secret"},
		{prefix: "/v1/pantry", path: "/v1/pantry/%2e%2e/secret"},
		{prefix: "/v1/pantry", path: "/v1/pantry/%2E%2E/secret"},
		{prefix: "/v1/pantry", path: "/v1/pantry/.%2e/secret"},
		{prefix: "/v1/pantry", path: "/v1/pantry/.."},
		{prefix: "/v1/pantry", path: "/v1/pantry/a/../../b"},

		{prefix: "/v1/pantry", path: "/v1/pantry/a%2Fb"},
		{prefix: "/v1/pantry", path: "/v1/pantry/%2f..%2f..%2fetc%2fpasswd"},
		{prefix: "/v1/pantry", path: "/v1/pantry/a%5Cb"},
		{prefix: "/v1/pantry", path: "/v1/pantry/a%2eb", want: "/a.b", ok: true},

		{prefix: "/v1/pantry", path: "/v1/pantry//items"},
		{prefix: "/v1/pantry", path: "/v1/pantry/a//b"},

		{prefix: "/v1/pantry", path: "/v1/pantry/%ff"},
		{prefix: "/v1/pantry", path: "/v1/pantry/%c0%ae"},

		{prefix: "/v1/pantry", path: "/v1/pantry/a%3Fb%23c", want: "/a%3Fb%23c", ok: true},
		{prefix: "/v1/pantry", path: "/v1/pantry/caf%C3%A9", want: "/caf%C3%A9", ok: true},
		{prefix: "/v1/pantry", path: "/v1/pantry/a%20b", want: "/a%20b", ok: true},
		{prefix: "/v1/pantry", path: "/v1/pantry/a+b", want: "/a%2Bb", ok: true},
		{prefix: "/v1/pantry", path: "/v1/pantry/.hidden", want: "/.hidden", ok: true},
		{prefix: "/v1/pantry", path: "/v1/pantry/~!*'()_-.", want: "/~!*'()_-.", ok: true},
		{prefix: "/v1/pantry", path: "/v1/pantry/%25", want: "/%25", ok: true},

		{prefix: "/v1", path: "/v1", want: "/", ok: true},
		{prefix: "/v1", path: "/v1/me", want: "/me", ok: true},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got, ok := UpstreamPath(tc.prefix, tc.path)

			if ok != tc.ok {
				t.Fatalf("UpstreamPath(%q, %q) ok=%v, want %v (got %q)", tc.prefix, tc.path, ok, tc.ok, got)
			}
			if ok && got != tc.want {
				t.Errorf("UpstreamPath(%q, %q) = %q, want %q", tc.prefix, tc.path, got, tc.want)
			}
		})
	}
}

func TestUpstreamPathWouldBePathCleanIfItWereAFilter(t *testing.T) {
	cases := []struct {
		path     string
		cleansTo string
	}{
		{path: "/v1/pantry/a%2Fb", cleansTo: "/v1/pantry/a/b"},
		{path: "/v1/pantry/../secret", cleansTo: "/v1/secret"},
		{path: "/v1/pantry//items", cleansTo: "/v1/pantry/items"},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if _, ok := UpstreamPath("/v1/pantry", tc.path); ok {
				t.Errorf("UpstreamPath(%q) accepted it, so %q would reach the upstream", tc.path, tc.cleansTo)
			}
		})
	}
}

func TestTheNormalisedPathIsTheURLParsersOwn(t *testing.T) {
	cases := []struct{ path, want string }{
		{path: "/a/..", want: "/"},
		{path: "/a/b/..", want: "/a/"},
		{path: "/..", want: "/"},
		{path: "/a/../..", want: "/"},
		{path: "/a/b/../..", want: "/"},
		{path: "/a/./", want: "/a/"},
		{path: "/a/.", want: "/a/"},
		{path: "/a/b/.", want: "/a/b/"},
		{path: "/a/b/./", want: "/a/b/"},
		{path: "/a//b/..", want: "/a//"},
		{path: "/a/b/../c", want: "/a/c"},
		{path: "/a/b/c/..", want: "/a/b/"},
		{path: "/a/b/../", want: "/a/"},
		{path: "/a/b/..//c", want: "/a//c"},
		{path: "/a/../../b", want: "/b"},
		{path: "/v1/pantry/./x", want: "/v1/pantry/x"},
		{path: "/v1/pantry/x/..", want: "/v1/pantry/"},
		{path: "/v1/pantry/../secret", want: "/v1/secret"},

		{path: "/v1/pantry/%2e%2e/secret", want: "/v1/secret"},
		{path: "/v1/pantry/%2E%2E/secret", want: "/v1/secret"},
		{path: "/v1/pantry/%2e/secret", want: "/v1/pantry/secret"},
		{path: "/v1/pantry/.%2e/secret", want: "/v1/secret"},
		{path: "/v1/pantry/%252e%252e/x", want: "/v1/pantry/%252e%252e/x"},

		{path: "/v1/pantry/%2e%2e%2fsecret", want: "/v1/pantry/%2e%2e%2fsecret"},
		{path: "/v1/pantry/%2f..%2fsecret", want: "/v1/pantry/%2f..%2fsecret"},
		{path: "/v1/pantry//x", want: "/v1/pantry//x"},
		{path: "/v1/pantry/a%2Fb", want: "/v1/pantry/a%2Fb"},
		{path: "/v1", want: "/v1"},
		{path: "/v1/", want: "/v1/"},
		{path: "/", want: "/"},
		{path: "/healthz", want: "/healthz"},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := NormaliseRequestPath(tc.path); got != tc.want {
				t.Errorf("NormaliseRequestPath(%q) = %q, want %q — the reference's URL parser answers %q, so the two disagree about which prefix claims this path",
					tc.path, got, tc.want, tc.want)
			}
		})
	}
}


func TestTheLongestPrefixWinsOnASegmentBoundary(t *testing.T) {
	table := RouteTable{
		"/v1/pantry":        {BaseURL: "http://pantry:8080"},
		"/v1/pantry/import": {BaseURL: "http://import:9000"},
		"/v1/catalog":       {BaseURL: "http://pantry:8080", Public: true},
		"/v1/catalog/admin": {BaseURL: "http://admin:9000"},
	}

	cases := []struct {
		path string
		want string
	}{
		{path: "/v1/pantry", want: "http://pantry:8080"},
		{path: "/v1/pantry/items", want: "http://pantry:8080"},
		{path: "/v1/pantry/import/x", want: "http://import:9000"},
		{path: "/v1/pantryx", want: ""},
		{path: "/v1/pantrys", want: ""},
		{path: "/v1/catalog/services", want: "http://pantry:8080"},
		{path: "/v1/catalog/admin/users", want: "http://admin:9000"},
		{path: "/v2/pantry", want: ""},
		{path: "/healthz", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			route, ok := ResolveRoute(table, tc.path)

			if tc.want == "" {
				if ok {
					t.Fatalf("%q resolved to %+v; a service cannot inherit a mount by sharing a name with another", tc.path, route)
				}
				return
			}
			if !ok {
				t.Fatalf("%q resolved to nothing, want %s", tc.path, tc.want)
			}
			if route.BaseURL != tc.want {
				t.Errorf("%q resolved to %s, want %s", tc.path, route.BaseURL, tc.want)
			}
		})
	}
}

func TestAPublicRouteIsDecidedByTheSameResolverThatDecidesTheDestination(t *testing.T) {
	table := RouteTable{
		"/v1/catalog":         {BaseURL: "http://pantry:8080", Public: true},
		"/v1/catalog/imports": {BaseURL: "http://pantry:8080"},
	}

	cases := []struct {
		path string
		want bool
	}{
		{path: "/v1/catalog", want: true},
		{path: "/v1/catalog/services", want: true},
		{path: "/v1/catalog/imports", want: false},
		{path: "/v1/catalog/imports/x", want: false},
		{path: "/v1/catalogue", want: false}, //nolint:misspell // a fixture PATH, not prose: it shares /v1/catalog's prefix without a path boundary, which is exactly what this case proves.
		{path: "/healthz", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := IsPublicRoute(table, tc.path); got != tc.want {
				t.Errorf("IsPublicRoute(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestAResolvedRouteIsACopyOfItsClaims(t *testing.T) {
	table := RouteTable{"/v1/pantry": {BaseURL: "http://pantry:8080", Principal: []string{"sub", "github_id"}}}

	first, ok := ResolveRoute(table, "/v1/pantry/x")
	if !ok {
		t.Fatal("the entry resolved to nothing")
	}
	first.Principal[0] = "aud"

	second, ok := ResolveRoute(table, "/v1/pantry/y")
	if !ok {
		t.Fatal("the entry resolved to nothing on the second ask")
	}
	if second.Principal[0] != "sub" {
		t.Errorf("the second resolution read %q; ResolveRoute must copy the declared claims", second.Principal[0])
	}
}

func TestAPublicRouteIsAcceptedWithNothingButAnOrigin(t *testing.T) {
	table, err := ParseRouteTable(`{"/v1/catalog":{"baseUrl":"http://pantry:8080","public":true}}`)
	if err != nil {
		t.Fatalf("ParseRouteTable refused the one entry MD18 is about: %v", err)
	}
	if !IsPublicRoute(table, "/v1/catalog/x") {
		t.Error("the entry parsed but is not public; MD18's flag would be decorative")
	}
}

func TestAnEmptyRouteTableVariableIsNoRoutingAtAll(t *testing.T) {
	for _, document := range []string{"", "   ", "\n\t "} {
		table, err := ParseRouteTable(document)
		if err != nil {
			t.Errorf("ParseRouteTable(%q) refused an empty variable: %v", document, err)
		}
		if table != nil {
			t.Errorf("ParseRouteTable(%q) returned %+v; an unset variable means no routing, not a table", document, table)
		}
	}
}

func TestEveryRouteTableRefusalNamesItsOwnRule(t *testing.T) {
	document := `{"/v1/%2e%2e":{"baseUrl":"ftp://pantry:8080"},"/v1/pantry":{"baseUrl":"http://pantry:8080","token":"a b"}}`

	_, err := ParseRouteTable(document)
	if err == nil {
		t.Fatal("ParseRouteTable accepted a table with two refusable entries")
	}
	if !strings.Contains(err.Error(), "%2e%2e") {
		t.Errorf("the refusal does not name the offending prefix, so it is not reproducible:\n  %v", err)
	}
}

func TestAnEntryWithNothingButAnOriginIsTheDefaultShape(t *testing.T) {
	table := RouteTable{"/v1/pantry": {BaseURL: "http://pantry:8080"}}

	checked, err := ValidateRouteTable(table)
	if err != nil {
		t.Fatalf("ValidateRouteTable refused the minimal entry: %v", err)
	}
	route, ok := ResolveRoute(checked, "/v1/pantry/x")
	if !ok {
		t.Fatal("the minimal entry claims nothing")
	}
	if route.Token != "" || route.Principal != nil || route.Public {
		t.Errorf("the minimal entry resolved to %+v; the zero value must mean no credential, no claims and not public", route)
	}
}

func TestTheQueryIsAppendedVerbatim(t *testing.T) {
	cases := []struct{ raw, want string }{
		{raw: "a=1&b=2", want: "?a=1&b=2"},
		{raw: "trace=%2Fsecret", want: "?trace=%2Fsecret"},
		{raw: "", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			if got := searchOf(mustParse(t, tc.raw)); got != tc.want {
				t.Errorf("searchOf(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
