// Package migrations exposes the versioned SQL migrations embedded in the binary.
package migrations

import "embed"

// Files contains every up and down migration used by the service.
//
//go:embed *.sql
var Files embed.FS
