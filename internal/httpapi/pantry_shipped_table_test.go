package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The shipped pantry route tables, held to the seam audit's finding F2.
//
// Pantry's write path verifies a gateway-signed principal assertion (RS256,
// `aud` = pantry's own origin, `sub` required). The minting mechanism is
// complete and tested (`table.go`, `proxy.go`, `assertion.go`) — but no
// shipped route table declared `principal` for pantry, so gateway minted
// nothing and every pantry write 401'd at the second hop.
//
// These tests read the tables the way an operator ships them — the
// `ROUTE_TABLE` documents in `docker-compose.yml` and
// `charts/gateway/values.yaml` — and assert the shape that closes the seam:
// reads stay on the existing public `/v1/pantry` prefix, a non-public write
// prefix declares `principal: ["sub"]` (sub only), the write prefix mints an
// assertion carrying `sub` and nothing else, and the read prefix mints
// nothing. A table that regresses to no-principal fails here rather than at
// pantry's second hop.

// shippedTableFile is one deployed ROUTE_TABLE document and where it lives,
// relative to this package's directory.
var shippedTableFiles = []string{
	"../../docker-compose.yml",
	"../../charts/gateway/values.yaml",
}

// shippedRouteTableDoc extracts the ROUTE_TABLE JSON document from a shipped
// file, whether the entry is active or commented out. Both shipped files
// carry the table as a single-line YAML scalar (single-quoted in compose,
// double-quoted in the chart); what matters here is the JSON, not whether
// the deployment has activated it.
func shippedRouteTableDoc(t *testing.T, path string) string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("cannot read the shipped table %s: %v", path, err)
	}

	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "#")
		trimmed = strings.TrimSpace(trimmed)
		value, ok := strings.CutPrefix(trimmed, "ROUTE_TABLE:")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			return value[1 : len(value)-1]
		}
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			inner := value[1 : len(value)-1]
			inner = strings.ReplaceAll(inner, `\/`, `/`)
			inner = strings.ReplaceAll(inner, `\"`, `"`)
			return inner
		}
		t.Fatalf("%s carries a ROUTE_TABLE in neither single nor double quotes: %q", path, value)
	}

	t.Fatalf("%s names no ROUTE_TABLE at all", path)
	return ""
}

// shippedEnvValues returns every value a shipped file assigns to an env
// variable, active lines and commented examples alike. A shipped file that
// stops naming the variable fails the caller, not this helper.
func shippedEnvValues(t *testing.T, path, name string) []string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}

	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "#")
		trimmed = strings.TrimSpace(trimmed)
		value, ok := strings.CutPrefix(trimmed, name+":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		out = append(out, value)
	}
	return out
}

// TestShippedPantryTablesMintSubOnlyOnTheWritePrefix is the F2 seam guard:
// the write prefix mints an assertion carrying `sub` (and only `sub`), and
// the read prefix mints nothing.
func TestShippedPantryTablesMintSubOnlyOnTheWritePrefix(t *testing.T) {
	for _, file := range shippedTableFiles {
		t.Run(file, func(t *testing.T) {
			table, err := ParseRouteTable(shippedRouteTableDoc(t, file))
			if err != nil {
				t.Fatalf("the shipped table in %s does not boot: %v", file, err)
			}

			// The write prefix: the one non-public pantry entry declaring claims.
			var writePrefix string
			writeEntries := 0
			for prefix, target := range table {
				if target.Public || target.Principal == nil {
					continue
				}
				if !strings.Contains(target.BaseURL, "pantry") {
					continue
				}
				writeEntries++
				writePrefix = prefix
			}
			if writeEntries != 1 {
				t.Fatalf("%s declares %d non-public pantry entries with principal claims, want exactly 1 — the write prefix. Without it gateway mints no assertion for pantry and every write 401s at the second hop", file, writeEntries)
			}
			if got := table[writePrefix].Principal; !reflect.DeepEqual(got, []string{"sub"}) {
				t.Fatalf("%s write prefix %s declares principal %q, want [\"sub\"] only — github_id is optional metadata pantry already treats as such, and a second claim is a second credential surface nobody asked for", file, writePrefix, got)
			}

			// The read prefix: the existing /v1/pantry entry stays public and
			// declares nothing.
			read, ok := table["/v1/pantry"]
			if !ok {
				t.Fatalf("%s lost the /v1/pantry read prefix", file)
			}
			if !read.Public {
				t.Errorf("%s /v1/pantry is no longer public; reads stay on the existing public prefix", file)
			}
			if read.Principal != nil {
				t.Errorf("%s /v1/pantry declares principal %q on a public entry — which refuses to boot, and would mint a signed statement about a request nobody was required to make", file, read.Principal)
			}

			// The behaviour, not just the declaration: the write prefix mints
			// an assertion carrying sub and only sub, bound to pantry's
			// origin; the read prefix mints nothing.
			key := testKey(t)
			minter, err := NewAssertionMinter(AssertionOptions{Key: key})
			if err != nil {
				t.Fatalf("NewAssertionMinter refused a generated key: %v", err)
			}
			proxy := newRouteProxy(proxyOptions{Routes: table, Assertion: minter})

			caller := principal(map[string]any{"github_id": 12345, "scope": "pantry:write"})

			writePath := writePrefix + "/projects"
			writeRoute, ok := ResolveRoute(table, writePath)
			if !ok || writeRoute.Prefix != writePrefix {
				t.Fatalf("%s: %s resolves to %q, want the write prefix %s", file, writePath, writeRoute.Prefix, writePrefix)
			}
			minted, err := proxy.assertionFor(withPrincipal(httptest.NewRequest(http.MethodPost, writePath, nil), caller), writeRoute)
			if err != nil {
				t.Fatalf("minting for the write prefix failed: %v", err)
			}
			if minted == "" {
				t.Fatalf("%s: the write prefix %s minted nothing — pantry verifies a gateway-signed assertion on writes, so this is the 401 at the second hop", file, writePrefix)
			}
			decoded := decodeAssertion(t, minted)
			decoded.verify(t, key.Public)
			if got := decoded.Claims["sub"]; got != caller.Sub {
				t.Errorf("the minted assertion carries sub=%v, want %q", got, caller.Sub)
			}
			if _, present := decoded.Claims["github_id"]; present {
				t.Errorf("the minted assertion carries github_id, which the write prefix did not declare — the assertion is minimal by declaration, not by what the caller holds")
			}
			if got := decoded.Claims["aud"]; got != writeRoute.BaseURL {
				t.Errorf("the minted assertion is bound to aud=%v, want the write entry's origin %q", got, writeRoute.BaseURL)
			}
			if got := decoded.Claims["aud"]; got != "http://pantry:8080" {
				t.Errorf("the minted assertion is bound to aud=%v, want pantry's in-cluster origin http://pantry:8080 — pantry's verifier demands aud == its own origin", got)
			}

			readRoute, ok := ResolveRoute(table, "/v1/pantry/projects")
			if !ok || !readRoute.Public {
				t.Fatalf("%s: /v1/pantry/projects does not resolve to the public read prefix", file)
			}
			if got, err := proxy.assertionFor(withPrincipal(httptest.NewRequest(http.MethodGet, "/v1/pantry/projects", nil), caller), readRoute); err != nil || got != "" {
				t.Errorf("%s: the public read prefix minted %q (err %v), want nothing — a public route has no verified caller to assert anything about", file, got, err)
			}
		})
	}
}

// TestShippedPantryTablesKeepAssertionTTLAtOrUnderTheCeiling holds the
// lifetime half of the seam: whatever ASSERTION_TTL_MS a shipped file sets
// must be at or under pantry's ten-minute ceiling.
func TestShippedPantryTablesKeepAssertionTTLAtOrUnderTheCeiling(t *testing.T) {
	for _, file := range shippedTableFiles {
		t.Run(file, func(t *testing.T) {
			values := shippedEnvValues(t, file, "ASSERTION_TTL_MS")
			if len(values) == 0 {
				t.Fatalf("%s sets no ASSERTION_TTL_MS alongside its pantry principal entries", file)
			}
			for _, value := range values {
				milliseconds, err := strconv.Atoi(value)
				if err != nil || milliseconds < 1 {
					t.Fatalf("%s sets ASSERTION_TTL_MS=%q, which is not a whole number of milliseconds", file, value)
				}
				if milliseconds > int(MaxAssertionTTL.Milliseconds()) {
					t.Fatalf("%s sets ASSERTION_TTL_MS=%q, above the %s ceiling pantry verifies against", file, value, MaxAssertionTTL)
				}
			}

			if names := shippedEnvValues(t, file, "ASSERTION_SIGNING_KEY_FILE"); len(names) == 0 {
				t.Fatalf("%s declares pantry principal entries but names no ASSERTION_SIGNING_KEY_FILE — with no key no assertion is minted on any route", file)
			}
		})
	}
}
