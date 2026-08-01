package main

import "embed"

// webFS embeds the static landing page and documentation so the binary is
// fully self-contained (works in a distroless/scratch image with no files).
//
//go:embed web/index.html web/docs.html
var webFS embed.FS
