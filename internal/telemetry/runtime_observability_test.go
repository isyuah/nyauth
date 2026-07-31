package telemetry

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/nyasharp/nyauth/internal/settings"
)

func TestTemporaryDebugRestoresBaseLevelAndNewSnapshotWins(t *testing.T) {
	level := new(slog.LevelVar)
	runtime := &Runtime{logLevel: level}
	first := settings.DefaultObservability()
	first.LogLevel = settings.LogLevelWarn
	firstExpiry := time.Now().Add(30 * time.Millisecond)
	first.DebugUntil = &firstExpiry
	runtime.ApplyObservability(settings.Versioned[settings.Observability]{Revision: 1, Value: first})
	if level.Level() != slog.LevelDebug {
		t.Fatalf("level = %s, want debug", level.Level())
	}

	second := settings.DefaultObservability()
	second.LogLevel = settings.LogLevelError
	secondExpiry := time.Now().Add(80 * time.Millisecond)
	second.DebugUntil = &secondExpiry
	runtime.ApplyObservability(settings.Versioned[settings.Observability]{Revision: 2, Value: second})
	time.Sleep(45 * time.Millisecond)
	if level.Level() != slog.LevelDebug {
		t.Fatalf("stale timer changed level to %s", level.Level())
	}
	time.Sleep(60 * time.Millisecond)
	if level.Level() != slog.LevelError {
		t.Fatalf("expired level = %s, want error", level.Level())
	}
}

func TestDynamicOTLPDisabledStatus(t *testing.T) {
	exporter := &dynamicOTLPExporter{}
	if status := exporter.status(); status.Configured || status.Available {
		t.Fatalf("disabled status = %#v", status)
	}
	if err := exporter.Export(context.Background(), nil); err != nil {
		t.Fatalf("disabled export: %v", err)
	}
}
