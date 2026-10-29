package equivalence

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/gateway/internal/httpapi"
)

const requestTimeout = 10 * time.Second

type caseSpec struct {
	name   string
	method string
	path   string

	body string

	headers map[string]string

	burst int

	scenarios []string
	want      limiterWant
}

type limiterWant struct {
	first int
	last  int

	remaining string
	counted   bool

	upstream int
}

type answer struct {
	status  int
	headers http.Header
	body    string
}

func askBurst(t *testing.T, base string, spec caseSpec) (answer, answer) {
	t.Helper()

	rounds := spec.burst
	if rounds < 1 {
		rounds = 1
	}

	first := ask(t, base, spec)
	last := first
	for round := 1; round < rounds; round++ {
		last = ask(t, base, spec)
	}
	return first, last
}

func ask(t *testing.T, base string, spec caseSpec) answer {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	var reader io.Reader
	if spec.body != "" {
		reader = strings.NewReader(spec.body)
	}
	req, err := http.NewRequestWithContext(ctx, spec.method, base+spec.path, reader)
	if err != nil {
		t.Fatalf("%s %s is not a request this check can build: %v", spec.method, spec.path, err)
	}
	if spec.body != "" {
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(len(spec.body))
	}
	for name, value := range spec.headers {
		req.Header.Set(name, value)
	}

	client := &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s did not answer: %v", spec.method, spec.path, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("%s %s: reading the body failed: %v", spec.method, spec.path, err)
	}

	return answer{status: res.StatusCode, headers: res.Header.Clone(), body: string(body)}
}

func mustHandler(t *testing.T, options httpapi.Options) http.Handler {
	t.Helper()

	handler, err := httpapi.New(options)
	if err != nil {
		t.Fatalf("httpapi.New refused the %+v configuration: %v", options, err)
	}
	return handler
}

func newGateway(t *testing.T, options httpapi.Options) string {
	t.Helper()

	server := httptest.NewServer(mustHandler(t, options))
	t.Cleanup(server.Close)
	return server.URL
}
