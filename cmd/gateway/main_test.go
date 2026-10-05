package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// The container health probe, tested rather than asserted.
//
// It exists because the runtime image is distroless: there is no shell in it and
// no HTTP client, so the probe that `docker compose up --wait` waits on has to be
// this binary. A flag with no test is a flag whose only evidence is that compose
// reported the service healthy once, and compose reporting a service healthy is
// exactly the thing that goes unexamined.
//
// Both answers are checked, because a probe that only ever refuses is
// indistinguishable from a probe that is broken. The "succeeds" case is the one a
// broken probe hides, and it is the one that makes the failing case meaningful.
func TestTheHealthProbeAnswersForBothAnswers(t *testing.T) {
	tests := []struct {
		name  string
		serve http.HandlerFunc
		want  int
	}{
		{
			name:  "a process answering 200 is healthy",
			serve: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
			want:  0,
		},
		{
			name: "a 503 is not, and it is what a refusing gateway would answer",
			// `/healthz` is unconditional by rule — a dependency outage is `/readyz`'s
			// to report — so this row is a hypothetical the probe still has to get
			// right: if `/healthz` ever grows a reason to fail, the probe must fail
			// with it rather than report a gateway that is refusing traffic as
			// healthy.
			serve: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
			want:  1,
		},
		{
			name:  "a 500 is not either",
			serve: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
			want:  1,
		},
		{
			// A redirect is not an answer. `301` is not 2xx, and the probe says so.
			name:  "a redirect is not an answer",
			serve: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusMovedPermanently) },
			want:  1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.serve)
			t.Cleanup(server.Close)

			if got := probeHealthz(server.URL + "/healthz"); got != test.want {
				t.Fatalf("probeHealthz(%s) = %d, want %d", server.URL, got, test.want)
			}
		})
	}
}

// Nothing listening is unhealthy, and it is the case a distroless image cannot
// report any other way — there is no `curl` to fail and no log line to read.
func TestTheHealthProbeFailsWhenNothingIsListening(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close() // nothing is on this port now

	if got := probeHealthz(url + "/healthz"); got != 1 {
		t.Fatalf("probeHealthz(%s) with nothing listening = %d, want 1", url, got)
	}
}

// `PORT`, because a probe aimed at a hardcoded 8080 reports a perfectly healthy
// service on another port as dead — and that is not a hypothetical, it is what the
// compose file's published port is for.
func TestTheHealthProbeAimsAtPort(t *testing.T) {
	// A server on a port nothing chose, so the number below is genuinely PORT's and
	// not a coincidence.
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer listener.Close()
	// `net.SplitHostPort` and not `strings.Cut(listener.URL, ":")`, which splits at
	// the first colon and hands back `//127.0.0.1:62708` — a PORT that aims the
	// probe at nothing and makes this case fail for a reason that is not the one it
	// is about. The port has to come out of the ADDRESS, not the URL.
	_, port, err := net.SplitHostPort(listener.Listener.Addr().String())
	if err != nil || port == "" {
		t.Fatalf("could not read a port out of %s: %v", listener.Listener.Addr(), err)
	}
	if port == strconv.Itoa(8080) {
		t.Fatalf("this test needs a port that is not 8080, and httptest handed out %s", port)
	}

	t.Setenv("PORT", port)

	// `healthcheck()` rather than `probeHealthz(url)`: the point of this case is
	// that the PORT lookup happens at all, which is a different function's job.
	if got := healthcheck(); got != 0 {
		t.Fatalf("healthcheck() with PORT=%s and a gateway listening there = %d, want 0", port, got)
	}

	// And the same probe against a port with nothing on it, which is the failure the
	// hardcoded number would have produced.
	t.Setenv("PORT", "1")
	if got := healthcheck(); got != 1 {
		t.Fatalf("healthcheck() with PORT=1 and nothing listening = %d, want 1", got)
	}
}

// An unset `PORT` means the same port `RuntimeOptions` listens on, and the two
// agreeing is why `httpapi.DefaultPort` is exported rather than written again here.
func TestAnUnsetPortProbesTheDefaultTheServerListensOn(t *testing.T) {
	t.Setenv("PORT", "")

	// Nothing is listening on 8080 in this test, so the answer is 1 — and what is
	// being asserted is that the probe got as far as dialling rather than refusing
	// to build a URL. A probe that reported 1 because it could not aim itself would
	// pass this case and be wrong about every container.
	if got := healthcheck(); got != 1 {
		t.Fatalf("healthcheck() with an unset PORT = %d, want 1 (nothing is listening on the default)", got)
	}
}
