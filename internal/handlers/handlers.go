// Package handlers wires HTTP requests to the offensive-security services.
package handlers

import (
	"io/fs"

	"pubapi/config"
	"pubapi/internal/service"
)

// Handler bundles configuration and shared state for all endpoints.
type Handler struct {
	cfg   *config.Config
	guard *service.Guard
	web   fs.FS // embedded static site (landing page + docs)
}

// New builds a Handler from configuration and the embedded web assets.
func New(cfg *config.Config, web fs.FS) *Handler {
	return &Handler{
		cfg:   cfg,
		guard: service.NewGuard(cfg.AllowPrivate),
		web:   web,
	}
}
