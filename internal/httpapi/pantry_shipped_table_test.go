package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)


var shippedTableFiles = []string{
	"../../docker-compose.yml",
	"../../charts/gateway/values.yaml",
}

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

func TestShippedPantryTablesMintSubOnlyOnTheWritePrefix(t *testing.T) {
	for _, file := range shippedTableFiles {
		t.Run(file, func(t *testing.T) {
			table, err := ParseRouteTable(shippedRouteTableDoc(t, file))
			if err != nil {
				t.Fatalf("the shipped table in %s does not boot: %v", file, err)
			}

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
			minted, err := proxy.assertionFor(withPrincipal(httptest.NewRequestWithContext(context.Background(), http.MethodPost, writePath, nil), caller), writeRoute)
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
			if strings.Contains(file, "charts/") {
				aud, _ := decoded.Claims["aud"].(string)
				if !strings.HasPrefix(aud, "https://") || strings.Contains(aud, ".svc.cluster.local") || !strings.Contains(aud, ".") {
					t.Errorf("the DEPLOYED chart mints aud=%q, which is not a public https origin — a box reaches the operated registry over HTTPS, so an in-cluster name here is a route to a service that does not exist (the live 503: GET https://api.anywaye.com/v1/pantry)", aud)
				}
			}

			readRoute, ok := ResolveRoute(table, "/v1/pantry/projects")
			if !ok || !readRoute.Public {
				t.Fatalf("%s: /v1/pantry/projects does not resolve to the public read prefix", file)
			}
			if got, err := proxy.assertionFor(withPrincipal(httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/pantry/projects", nil), caller), readRoute); err != nil || got != "" {
				t.Errorf("%s: the public read prefix minted %q (err %v), want nothing — a public route has no verified caller to assert anything about", file, got, err)
			}
		})
	}
}

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
