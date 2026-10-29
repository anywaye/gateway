package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)


// VHostTarget is one hostname's backend: a base URL and gateway's credential for it.
type VHostTarget struct {
	BaseURL string

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

type rawVHost struct {
	BaseURL string  `json:"baseUrl"`
	Token   *string `json:"token"`
}

// ParseVHostTable reads the table an operator wrote and validates it.
//
// `VHOST_TABLE={"auth.anywaye.test":{"baseUrl":"http://127.0.0.1:19080"}}`.
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

func effectiveHost(r *http.Request) string {
	host := strings.ToLower(r.Host)
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return strings.TrimSuffix(host, ".")
}

func isGatewayPath(path string) bool {
	if _, ok := ProbePaths[path]; ok {
		return true
	}
	if path == "/auth" || strings.HasPrefix(path, "/auth/") {
		return true
	}
	return isGatewayOwned(path)
}

func vhostGate(table VHostTable, timeout time.Duration, assertion *AssertionMinter) func(http.Handler) http.Handler {
	if table == nil {
		return nil
	}
	proxy := newRouteProxy(proxyOptions{Timeout: timeout, Assertion: assertion})
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

			upstream, ok := UpstreamPath("", path)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			route := ResolvedRoute{Prefix: "vhost:" + effectiveHost(r), BaseURL: target.BaseURL, Token: target.Token}
			dest := route.BaseURL + upstream + searchOf(r.URL)
			response := proxy.call(r, route, dest)

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
