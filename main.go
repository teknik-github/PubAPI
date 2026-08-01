// PubAPI OffSec — a public HTTP API for offensive-security reconnaissance
// and utilities. Intended for authorized security testing and research.
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pubapi/config"
	"pubapi/internal/router"
	"pubapi/internal/service"
)

func main() {
	cfg := config.Load()
	service.SetCacheEnabled(cfg.CacheEnabled)
	engine := router.New(cfg, webFS)

	srv := &http.Server{
		Addr:              net.JoinHostPort(cfg.Host, cfg.Port),
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Start the server in the background so we can wait for a shutdown signal.
	go func() {
		log.Printf("PubAPI OffSec listening on %s (mode=%s, allow_private=%v)",
			srv.Addr, cfg.Mode, cfg.AllowPrivate)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Graceful shutdown on SIGINT/SIGTERM.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("forced shutdown: %v", err)
	}
	log.Println("stopped")
}
