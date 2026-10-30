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

	"github.com/anywaye/gateway/internal/httpapi"
	"github.com/anywaye/gateway/internal/telemetry"
)

const healthcheckTimeout = 2 * time.Second

func healthcheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = httpapi.DefaultPort
	}
	return probeHealthz("http://127.0.0.1:" + port + "/healthz")
}

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
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return 1
	}
	return 0
}

const (
	readHeaderTimeout = 10 * time.Second
	writeTimeout      = 30 * time.Second

	shutdownGrace = 20 * time.Second
)

func main() {
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

	ctx := context.Background()
	flush, err := telemetry.Install(ctx, telemetry.Options{
		Endpoint:  telemetry.Endpoint(),
		Disabled:  !telemetry.Enabled(),
		LookupEnv: os.Getenv,
	})
	if err != nil {
		return err
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := flush(flushCtx); err != nil {
			log.Printf("gateway: flushing telemetry on the way out failed: %v", err)
		}
	}()
	if reason := telemetry.NoOpReason(); reason != "" {
		log.Printf("gateway: telemetry is off (%s)", reason)
	}

	httpapi.InitErrorReporting()

	handler, err := httpapi.New(config.Options)
	if err == nil {
		handler = httpapi.RecoverMiddleware(handler)
	}
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              config.Addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
	}

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
