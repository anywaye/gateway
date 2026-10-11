package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Which hostname goes to which backend, in configuration rather than in code.
//
// The routing table in `table.go` is PATH-PREFIX based and has no host awareness:
// `{"baseUrl": …}` under `/v1/pantry` answers the same backend whatever `Host` the
// caller sent. That is the API surface, and it stays that way. This file is the
// layer the plan's `api`/`auth` vhost split needs: `api.cafaye.test` is the API
// route table, `auth.cafaye.test` is identity's OIDC face, `cafaye.test` is the
// BFF/app upstream — three names, three backends, one gateway.
//
// ## WHY A SECOND TABLE AND NOT HOST FIELDS ON THE ENTRIES
//
// A host field on a `RouteTarget` would say "this prefix, but only on this host",
// which is a filter on the API surface. The vhost split is not a filter on it:
// `/.well-known/openid-configuration` and `/oidc/*` are not under `/v1/` and no
// `ROUTE_TABLE` entry can legally claim them (`checkPrefix` refuses anything
// outside the mount). A host qualifier on entries that cannot name the paths is a
// field that configures nothing, and a field that configures nothing is the exact
// failure `TestTheRuntimeReaderReadsExactlyTheseVariables` exists to catch. So the
// vhost table maps a whole hostname to a whole backend, and the two tables answer
// two different questions: the vhost table says *which backend this name is*, the
// path table says *which prefix of the API surface goes where*.
//
// ## WHY NO PUBLIC/PRINCIPAL/SCOPES HERE
//
// A second scope table is a second thing to get stale, and the path table is
// already the only scope table (`accountRouteScopes`'s argument, one file over in
// spirit). A vhost entry declares transport — "this name is this backend" — and
// authentication stays where it was: the path table's gates for `/v1/*`, the
// backend's own for everything else. An `auth.cafaye.test` entry carrying a scope
// would be a scope no path-table walk reads and no matrix row holds, which is how
// a route gets gated in exactly one of the two places a reader looks.

// VHostTarget is one hostname's backend: a base URL and gateway's credential for it.
type VHostTarget struct {
	// The backend's base URL: http(s), no path, no query, no fragment, no
	// credentials — the same rule `checkBaseURL` applies to a path entry, because
	// it is the same mistake (a password in a log line, a path swallowing the
	// caller's).
	BaseURL string

	// The credential gateway presents to this backend, as a bearer token. Empty
	// means none is attached — which is what the OIDC face wants, because identity
	// authenticates the caller itself and a gateway-invented credential would be a
	// second identity the backend never asked for.
	Token string
}

// VHostTable is hostname -> backend. The whole of the vhost configuration.
type VHostTable map[string]VHostTarget

// ValidateVHostTable checks a table and returns a fresh one.
//
// Nil stays nil: no vhost configuration is a working gateway, the one whose
// routing is the path table alone. A non-nil table is validated in sorted hostname
// order, so two bad entries name the same one on every run.
func ValidateVHostTable(table VHostTable) (VHostTable, error) {
	if table == nil {
		return nil, nil
	}
	if len(table) == 0 {
		return nil, fmt.Errorf("%w: a vhost table must name at least one hostname. An empty one routes nothing, and an operator who meant to configure the api/auth split would never find out from a 404", ErrNotConfigured)
	}

	hosts := make([]string, 0, len(table))
	for host := range table {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	checked := make(VHostTable, len(table))
	for _, host := range hosts {
		target := table[host]
		if err := checkVHostName(host); err != nil {
			return nil, err
		}
		base, err := checkBaseURL("vhost "+host, target.BaseURL)
		if err != nil {
			return nil, err
		}
		if err := checkToken("vhost "+host, target.Token); err != nil {
			return nil, err
		}
		checked[strings.ToLower(host)] = VHostTarget{BaseURL: base, Token: target.Token}
	}

	return checked, nil
}

// checkVHostName refuses a hostname that is not one.
//
// A name carrying a scheme (`https://auth…`), a port (`auth…:443`), a path or a
// trailing dot is an operator spelling the address the way a browser bar shows it
// rather than the way the `Host` header carries it. Matching would then be against
// a normalised header and an unnormalised entry, which agree only when nobody
// makes the obvious mistake — so the entry is refused at boot and the message says
// what to type instead.
func checkVHostName(host string) error {
	if host == "" {
		return fmt.Errorf("%w: vhostTable: hostnames must be non-empty strings", ErrNotConfigured)
	}
	if host != strings.ToLower(host) {
		return fmt.Errorf("%w: vhostTable: %q must be lowercase. Host matching is case-insensitive and the table is read that way, so an entry that is not already lowercase is a table that does not say what it means", ErrNotConfigured, host)
	}
	if strings.ContainsAny(host, " \t\r\n/:?#@") || strings.Contains(host, "*") {
		return fmt.Errorf("%w: vhostTable: %q is not a bare hostname. Write the host alone — no scheme, no port, no path, no wildcard", ErrNotConfigured, host)
	}
	return nil
}

// rawVHost is one entry as the JSON carries it.
type rawVHost struct {
	BaseURL string  `json:"baseUrl"`
	Token   *string `json:"token"`
}

// ParseVHostTable reads the table an operator wrote and validates it.
//
// `VHOST_TABLE={"auth.cafaye.test":{"baseUrl":"http://127.0.0.1:19080"}}`.
// Empty or whitespace-only is no table, the same rule `routesFromEnv` applies to
// `ROUTE_TABLE`: an unset split is a gateway whose routing is the path table
// alone, not a refusal. `"token": ""` is refused for the reason `rawTargetOf`
// gives: an empty token is not a backend that takes no credential, and the two
// spellings must stay distinguishable.
func ParseVHostTable(document string) (VHostTable, error) {
	if trimSpace(document) == "" {
		return nil, nil
	}

	var entries map[string]json.RawMessage
	if err := json.Unmarshal([]byte(document), &entries); err != nil {
		return nil, fmt.Errorf("%w: gateway: VHOST_TABLE must be a JSON object mapping a hostname to {\"baseUrl\": …, \"token\"?: …}, and it is not one", ErrNotConfigured)
	}

	table := make(VHostTable, len(entries))
	for host, raw := range entries {
		var decoded rawVHost
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return VHostTable{}, fmt.Errorf("%w: vhostTable: %s must be an object with a baseUrl", ErrNotConfigured, host)
		}
		target := VHostTarget{BaseURL: decoded.BaseURL}
		if decoded.Token != nil {
			if *decoded.Token == "" {
				return nil, fmt.Errorf("%w: vhostTable: %s token must be a non-empty string. An empty token is not a backend that takes no credential — omit the field for that, so the difference between the two spellings survives", ErrNotConfigured, host)
			}
			target.Token = *decoded.Token
		}
		table[host] = target
	}

	return ValidateVHostTable(table)
}

// effectiveHost is the hostname a request is routed on: `r.Host` lowercased with
// any port stripped.
//
// `X-Forwarded-Host` is deliberately NOT read, and the reason is `proxy.go`'s
// first rule: no code path builds a request out of a header. A caller-settable
// header choosing the backend would let a caller choose which service answers —
// the path table's gates would still run, but the backend selection itself would
// be caller-controlled, which is the confused-deputy shape one file over. An edge
// in front of this gateway preserves `Host`; that is what the header is for.
func effectiveHost(r *http.Request) string {
	host := strings.ToLower(r.Host)
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return strings.TrimSuffix(host, ".")
}

// isGatewayPath reports whether a path is gateway's own and must never be
// vhost-proxied, whatever `Host` arrived.
//
// The probes (`/healthz`, `/readyz`) answer even through `api.cafaye.test` —
// readyz staying green on the API name is one of the loop's proofs — and the
// browser surface (`/auth/*`), `/v1/me` and the `/v1/api-keys` management routes
// are answered here for the same reason `routeProxy.handle` names its exclusion:
// a vhost entry claiming them would relay gateway's own routes to a backend that
// has never heard of them.
func isGatewayPath(path string) bool {
	if _, ok := ProbePaths[path]; ok {
		return true
	}
	if path == "/auth" || strings.HasPrefix(path, "/auth/") {
		return true
	}
	return isGatewayOwned(path)
}

// vhostGate routes one hostname to one backend, or nil when there is no table.
//
// Mounted AFTER the credential and scope gates and BEFORE the pass-through, and
// the position is the whole argument: the limiter and the telemetry already ran
// (a vhost request is counted and spanned like any other), the path table's gates
// had their say on `/v1/*` (the split changes nothing about the API surface's
// authz), and a request nothing claimed still falls through to the pass-through
// and then the router. A vhost match for a gateway-owned path falls through too,
// so the probes and the browser surface are never proxied away.
//
// Nil when the table is nil, for the reason every other gate in this file is nil
// when unconfigured: a gate that cannot refuse is not a gate, and the honest
// spelling of "there is none" is the absence.
func vhostGate(table VHostTable, timeout time.Duration, assertion *AssertionMinter) func(http.Handler) http.Handler {
	if table == nil {
		return nil
	}
	proxy := newRouteProxy(proxyOptions{Timeout: timeout, Assertion: assertion})
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The raw spelling, never `URL.Path`, for `proxy.go`'s reason: a
			// traversal is a traversal before it is decoded.
			path := NormaliseRequestPath(r.URL.EscapedPath())
			if isGatewayPath(path) {
				next.ServeHTTP(w, r)
				return
			}
			target, ok := table[effectiveHost(r)]
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			// Rebuilt, never forwarded as received: the full path crosses to the
			// backend, but through the same segment decoder that makes a traversal
			// inexpressible on the path table. The prefix is empty because a vhost
			// owns the whole name rather than a subtree of it.
			upstream, ok := UpstreamPath("", path)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			route := ResolvedRoute{Prefix: "vhost:" + effectiveHost(r), BaseURL: target.BaseURL, Token: target.Token}
			dest := route.BaseURL + upstream + searchOf(r.URL)
			response := proxy.call(r, route, dest)

			// The same tail `routeProxy.handle` applies to a path-table answer: a
			// 2xx or a 4xx is the backend's own contract and crosses unchanged,
			// everything else is gateway's 503. Two spellings of one rule would
			// drift, so a change here is a change there.
			if response == nil {
				writeProblem(w, r, unreachableUpstream())
				return
			}
			if IsRelayableStatus(response.status) {
				relayUpstream(w, response)
				return
			}
			writeProblem(w, r, unusableUpstream(dest, response))
		})
	}
}
