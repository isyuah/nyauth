package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/nyasharp/nyauth/internal/database"
)

type readinessCheck struct {
	name  string
	check func(context.Context) error
}

type readinessState struct {
	accepting atomic.Bool
	checks    []readinessCheck
}

func (s *Server) runtimeReadinessChecks() []readinessCheck {
	return []readinessCheck{
		{name: "database", check: func(ctx context.Context) error { return s.db.Ping(ctx) }},
		{name: "redis", check: func(ctx context.Context) error { return s.rdb.Ping(ctx).Err() }},
		{name: "schema", check: func(ctx context.Context) error { return database.ValidateSchemaVersion(ctx, s.db) }},
		{name: "jwk", check: func(ctx context.Context) error {
			_, _, err := s.jwkManager.GetPrivateKey(ctx)
			return err
		}},
		{name: "providers", check: func(context.Context) error {
			if !s.readiness.accepting.Load() || !s.providerMgr.Ready() {
				return fmt.Errorf("provider snapshot has not completed its initial load")
			}
			return nil
		}},
	}
}

func (s *Server) handleLiveness(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
}

func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Server.ReadinessTimeout)
	defer cancel()
	ready := true
	for _, candidate := range s.readiness.checks {
		started := time.Now()
		if err := candidate.check(ctx); err != nil {
			s.telemetry.RecordDependency(r.Context(), candidate.name, "readiness", "failure", time.Since(started))
			ready = false
			slog.WarnContext(r.Context(), "readiness check failed", "component", candidate.name, "error_type", fmt.Sprintf("%T", err))
		} else {
			s.telemetry.RecordDependency(r.Context(), candidate.name, "readiness", "success", time.Since(started))
		}
	}
	if !ready {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
