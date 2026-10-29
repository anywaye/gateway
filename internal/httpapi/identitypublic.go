package httpapi

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)


type identityPublicRoute struct {
	Method   string
	Template string
}

var identityPublicRoutes = []identityPublicRoute{
	{Method: http.MethodPost, Template: "/v1/agents"},
	{Method: http.MethodGet, Template: "/v1/agents/claim/{token}"},
	{Method: http.MethodGet, Template: "/v1/auth/oauth/{provider}"},
	{Method: http.MethodGet, Template: "/v1/auth/oauth/{provider}/callback"},
	{Method: http.MethodPost, Template: "/v1/email-changes/current-address"},
	{Method: http.MethodPost, Template: "/v1/email-changes/new-address"},
	{Method: http.MethodPost, Template: "/v1/email-verifications"},
	{Method: http.MethodPost, Template: "/v1/email-verifications/confirm"},
	{Method: http.MethodPost, Template: "/v1/password-resets"},
	{Method: http.MethodPost, Template: "/v1/password-resets/confirm"},
	{Method: http.MethodPost, Template: "/v1/session"},
	{Method: http.MethodPost, Template: "/v1/session-links/redeem"},
	{Method: http.MethodPost, Template: "/v1/session/mfa"},
	{Method: http.MethodPost, Template: "/v1/signup-timestamp"},
	{Method: http.MethodPost, Template: "/v1/users"},
}

func isIdentityPublicRoute(method, path string) bool {
	target := pathname(path)
	if len(target) > 1 {
		target = strings.TrimSuffix(target, "/")
	}
	got := strings.Split(strings.TrimPrefix(target, "/"), "/")

	for _, route := range identityPublicRoutes {
		if method != route.Method {
			continue
		}
		want := strings.Split(strings.TrimPrefix(route.Template, "/"), "/")
		if len(got) != len(want) {
			continue
		}
		match := true
		for i := range want {
			if isTemplateSegment(want[i]) {
				if got[i] == "" {
					match = false
					break
				}
				continue
			}
			if got[i] != want[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func isTemplateSegment(segment string) bool {
	return len(segment) > 2 && strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}")
}

func checkIdentityBaseURL(value string) (string, error) {
	parsed, err := parseAbsoluteURL(value)
	if err != nil {
		return "", fmt.Errorf("%w: identity: IdentityBaseURL must be an absolute http(s) URL, got %q", ErrNotConfigured, value)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("%w: identity: IdentityBaseURL must be a base URL with no path, got %q. The caller's path is appended to it", ErrNotConfigured, value)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: identity: IdentityBaseURL must carry no query or fragment, got %q", ErrNotConfigured, value)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("%w: identity: IdentityBaseURL must not carry credentials, got %q. A credential belongs in a header, not in an authority that gets written to a log", ErrNotConfigured, redactUserinfo(value))
	}

	return originOf(parsed), nil
}

func compareIdentityPublicRoutes(declared []string) (missing, extra []string) {
	compiled := make(map[string]struct{}, len(identityPublicRoutes))
	for _, route := range identityPublicRoutes {
		compiled[route.Method+" "+route.Template] = struct{}{}
	}

	seen := make(map[string]struct{}, len(declared))
	for _, entry := range declared {
		seen[entry] = struct{}{}
		if _, ok := compiled[entry]; !ok {
			missing = append(missing, entry)
		}
	}
	for _, route := range identityPublicRoutes {
		entry := route.Method + " " + route.Template
		if _, ok := seen[entry]; !ok {
			extra = append(extra, entry)
		}
	}

	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}
