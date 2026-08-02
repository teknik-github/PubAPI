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
	"strings"
	"syscall"
	"time"

	"pubapi/config"
	"pubapi/internal/auth"
	"pubapi/internal/router"
	"pubapi/internal/service"
	"pubapi/internal/store"
)

func main() {
	cfg := config.Load()

	// CLI subcommand: create an admin account and exit.
	//   pubapi create-admin <email> <password>
	if len(os.Args) >= 2 && os.Args[1] == "create-admin" {
		runCreateAdmin(cfg, os.Args[2:])
		return
	}

	// CLI subcommand: liveness probe for container healthchecks.
	//   pubapi healthcheck  -> exit 0 if the local server answers /health
	if len(os.Args) >= 2 && os.Args[1] == "healthcheck" {
		runHealthcheck(cfg)
		return
	}

	service.SetCacheEnabled(cfg.CacheEnabled)

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("failed to open database %q: %v", cfg.DBPath, err)
	}
	defer st.Close()
	bootstrapAdmin(st, cfg.AdminEmail, cfg.AdminPassword)

	engine := router.New(cfg, webFS, st)

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

// runHealthcheck probes the local /health endpoint and exits 0 (healthy) or 1.
// Used as the container HEALTHCHECK since the distroless image has no curl.
func runHealthcheck(cfg *config.Config) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + cfg.Port + "/health")
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	os.Exit(0)
}

// runCreateAdmin creates an admin account from the CLI, then exits.
func runCreateAdmin(cfg *config.Config, args []string) {
	if len(args) < 2 {
		log.Fatal("usage: pubapi create-admin <email> <password>")
	}
	email := strings.ToLower(strings.TrimSpace(args[0]))
	password := args[1]
	if email == "" || len(password) < 8 {
		log.Fatal("email required and password must be at least 8 characters")
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("failed to open database %q: %v", cfg.DBPath, err)
	}
	defer st.Close()
	if _, err := st.GetUserByEmail(email); err == nil {
		log.Fatalf("a user with email %q already exists", email)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		log.Fatalf("failed to hash password: %v", err)
	}
	u, err := st.CreateUser(email, hash, "admin", true)
	if err != nil {
		log.Fatalf("failed to create admin: %v", err)
	}
	log.Printf("admin account created: %s (id=%d) in %s", u.Email, u.ID, cfg.DBPath)
}

// bootstrapAdmin creates the admin account from env on first run, if configured
// and not already present.
func bootstrapAdmin(st *store.Store, email, password string) {
	if email == "" || password == "" {
		if n, _ := st.CountAdmins(); n == 0 {
			log.Println("no admin account yet — set ADMIN_EMAIL and ADMIN_PASSWORD to create one")
		}
		return
	}
	if _, err := st.GetUserByEmail(email); err == nil {
		return // already exists
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		log.Printf("bootstrap admin: failed to hash password: %v", err)
		return
	}
	if _, err := st.CreateUser(email, hash, "admin", true); err != nil {
		log.Printf("bootstrap admin: %v", err)
		return
	}
	log.Printf("bootstrap admin account created: %s", email)
}
