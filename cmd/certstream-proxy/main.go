// Command certstream-proxy is a small authenticated CONNECT proxy for fetching
// from CT logs via a different egress address than the main certstream server.
//
// It is deliberately narrow: CONNECT only, to an explicit allowlist of hosts
// and ports, behind a shared token and an optional source-IP allowlist.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/proxy"
)

// version is overwritten at build time by the release pipeline.
var version = "dev"

func main() {
	configPath := flag.String("config", "config.yaml", "Path to the proxy config file")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("certstream-proxy %s\n", version)
		return
	}

	cfg, err := proxy.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("certstream-proxy: %v\n", err)
	}

	server := proxy.NewServer(cfg)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-signals
		log.Printf("Received signal %v, shutting down...\n", sig)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Error during shutdown: %v\n", err)
		}
	}()

	log.Printf("Starting certstream-proxy %s\n", version)

	// Shutdown makes ListenAndServe return ErrServerClosed; that is a clean stop,
	// not a failure, so it must not exit non-zero.
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("certstream-proxy: %v\n", err)
	}
}
