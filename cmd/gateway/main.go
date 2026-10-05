// Command gateway serves the cafaye public gateway.
//
// The one thing in this file that matters is what it does NOT do: it does not
// read a configuration value, decide a limit, verify a token or name an
// upstream. It reads the environment through `httpapi.RuntimeOptions` — the one
// function in this module that is allowed to — hands the result to
// `httpapi.New` as an argument, and listens.
//
// `src/index.ts` (removed at cutover) is the same shape in TypeScript, and the boundary is the
// property `guard/AGENTS.md` asks for: *"Configuration arrives as an argument,
// never as a module-level global read from the environment, so a test can build
// two differently-configured apps in one process."* Importing this package does
// not listen, because `main` is a function — Go's equivalent of TypeScript's
// `import.meta.main`, and the reason the handler is constructible without a
// socket.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cafaye/gateway/internal/httpapi"
)

// healthcheckTimeout bounds the probe. Short, because a compose healthcheck that
// takes thirty seconds to fail is a healthcheck whose interval is a lie, and this
// one runs every few seconds for the life of the container.
const healthcheckTimeout = 2 * time.Second

// healthcheck reports this process's own liveness as an exit status: 0 answering,
// 1 not.
//
// `/healthz` and NOT `/readyz`, and the difference is this repository's rule rather
// than a preference. `identity`'s compose healthcheck probes `/readyz`, because
// there readiness is the one that consults the database and a probe that reports
// healthy against a database that is gone is reporting a service that answers 503
// to everybody. gateway's `/readyz` consults identity and Redis, and **a
// dependency outage must not restart the gateway**: `/healthz` is the one probe a
// restart can usefully act on, because it asks whether this process is answering
// and nothing else. The same reasoning as `docker-compose.yml`'s healthcheck
// paragraph, which is where an operator reads it.
//
// So this reports liveness, and a gateway whose identity is unreachable is a
// gateway `/healthz` calls healthy and `/readyz` names the dependency in. That is
// the split, and putting it in the probe is what keeps it from being decided again
// by whoever writes the next health check.
func healthcheck() int {
	// `PORT` rather than a hardcoded 8080, because a container started on another
	// port has to be probeable and a probe aimed at 8080 reports a perfectly healthy
	// service as dead.
	port := os.Getenv("PORT")
	if port == "" {
		port = httpapi.DefaultPort
	}
	return probeHealthz("http://127.0.0.1:" + port + "/healthz")
}

// probeHealthz asks one URL whether it is alive, and answers 0 or 1.
//
// Split from `healthcheck` so a test can point it at an `httptest.Server` and read
// both answers — a check that has only ever refused is indistinguishable from one
// that is broken, which is the same argument the Redis tier's "a test that has never
// run its commands proves nothing" makes.
//
// The body is read and discarded rather than the connection simply closed: closing
// without draining shows up in the server's own logs as a broken pipe on a request
// it already answered, every few seconds, forever.
func probeHealthz(url string) int {
	ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 1
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 1
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)

	// Any 2xx, not `== 200`: what is being asserted is "this process is answering",
	// and a probe that hardcodes one status code breaks the day the liveness route
	// is allowed to answer something else.
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return 1
	}
	return 0
}

// The two timeouts, and both are non-zero.
//
// `ReadHeaderTimeout` is the one that matters and the reason `http.Server` is
// used rather than a bare listener: without it a client that opens a connection
// and never sends a line holds a goroutine forever, and the process stops
// accepting long before it runs out of memory. `WriteTimeout` is bounded too,
// for a client that sends headers and then dribbles — a slowloris that gets past
// the header deadline.
//
// There is no `ReadTimeout` on top of `ReadHeaderTimeout`, because the request
// body of the one request this service will accept a body on is 4 KiB and the
// contract says so. The header deadline is the one that protects the process.
const (
	readHeaderTimeout = 10 * time.Second
	writeTimeout      = 30 * time.Second

	// How long a SIGTERM gets to finish in-flight requests before the listener
	// is closed anyway. Long enough for a proxy to notice and route elsewhere,
	// short enough that an orchestrator's kill does not arrive first.
	shutdownGrace = 20 * time.Second
)

func main() {
	// `-healthcheck` is the container health probe, and it is a flag on this binary
	// rather than a request from outside the container for one reason: the runtime
	// image is `gcr.io/distroless/static-debian12:nonroot`, which has no shell and
	// no HTTP client. The alternatives were a `build:` stanza adding curl — a supply
	// chain in the image of the service every caller's credential crosses — or no
	// healthcheck at all, which is worse than either: `docker compose up --wait`
	// would then report the service up the instant the process starts, which is
	// before anything is listening.
	if len(os.Args) == 2 && os.Args[1] == "-healthcheck" {
		os.Exit(healthcheck())
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "gateway: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	config, err := httpapi.RuntimeOptions(httpapi.OSEnv)
	if err != nil {
		return err
	}

	handler, err := httpapi.New(config.Options)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              config.Addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
	}

	// Shut down on SIGTERM or SIGINT, and treat the *second* one as "now". A
	// first signal starts a graceful drain; an orchestrator's escalation is a
	// second signal or a kill, and a process that ignores the second is a
	// deployment that restarts the hard way.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		stop()

		grace, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()

		if err := server.Shutdown(grace); err != nil {
			log.Printf("gateway: shutdown did not finish in %s: %v", shutdownGrace, err)
		}
	}()

	log.Printf("gateway listening on %s", config.Addr)

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("listening on %s: %w", config.Addr, err)
	}
	return nil
}
