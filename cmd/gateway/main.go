// Command gateway serves the cafaye public gateway.
//
// The one thing in this file that matters is what it does NOT do: it does not
// read a configuration value, decide a limit, verify a token or name an
// upstream. It reads the environment through `httpapi.RuntimeOptions` — the one
// function in this module that is allowed to — hands the result to
// `httpapi.New` as an argument, and listens.
//
// `src/index.ts` is the same shape in TypeScript, and the boundary is the
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
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cafaye/gateway/internal/httpapi"
)

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
