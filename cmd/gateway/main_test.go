package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/anywaye/gateway/internal/httpapi"
)

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
			serve: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
			want:  1,
		},
		{
			name:  "a 500 is not either",
			serve: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
			want:  1,
		},
		{
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

func TestTheHealthProbeFailsWhenNothingIsListening(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()

	if got := probeHealthz(url + "/healthz"); got != 1 {
		t.Fatalf("probeHealthz(%s) with nothing listening = %d, want 1", url, got)
	}
}

func TestTheHealthProbeAimsAtPort(t *testing.T) {
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Listener.Addr().String())
	if err != nil || port == "" {
		t.Fatalf("could not read a port out of %s: %v", listener.Listener.Addr(), err)
	}
	if port == strconv.Itoa(8080) {
		t.Fatalf("this test needs a port that is not 8080, and httptest handed out %s", port)
	}

	t.Setenv("PORT", port)

	if got := healthcheck(); got != 0 {
		t.Fatalf("healthcheck() with PORT=%s and a gateway listening there = %d, want 0", port, got)
	}

	t.Setenv("PORT", "1")
	if got := healthcheck(); got != 1 {
		t.Fatalf("healthcheck() with PORT=1 and nothing listening = %d, want 1", got)
	}
}

func TestAnUnsetPortProbesTheDefaultTheServerListensOn(t *testing.T) {
	t.Setenv("PORT", "")

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not hold a port for the probe to find: %v", err)
	}
	defer listener.Close()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	restore := httpapi.DefaultPort
	httpapi.DefaultPort = port
	t.Cleanup(func() { httpapi.DefaultPort = restore })

	if got := healthcheck(); got != 0 {
		t.Fatalf("healthcheck() with an unset PORT = %d, want 0 — the probe found the default port %s listening", got, port)
	}

	_ = server.Close()
	_ = listener.Close()

	if got := healthcheck(); got != 1 {
		t.Fatalf("healthcheck() with the default port %s silent = %d, want 1 — the probe aimed at the injected default, not at a hardcoded 8080", port, got)
	}
}
