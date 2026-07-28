package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/servicecontrol"
)

func TestLivenessDoesNotDependOnRuntimeDependencies(t *testing.T) {
	t.Parallel()
	recorder := httptest.NewRecorder()
	(&Server{}).handleLiveness(recorder, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"alive"`) {
		t.Fatalf("liveness response = %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", recorder.Header().Get("Cache-Control"))
	}
}

func TestReadinessChecksEveryComponentAndHidesFailureDetails(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := &Server{cfg: &config.Config{Server: config.ServerConfig{ReadinessTimeout: time.Second}}}
	server.readiness.checks = []readinessCheck{
		{name: "database", check: func(context.Context) error {
			calls.Add(1)
			return errors.New("password=do-not-leak")
		}},
		{name: "redis", check: func(context.Context) error {
			calls.Add(1)
			return nil
		}},
	}
	recorder := httptest.NewRecorder()
	server.handleReadiness(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness status = %d", recorder.Code)
	}
	if calls.Load() != 2 {
		t.Fatalf("readiness calls = %d", calls.Load())
	}
	if strings.Contains(recorder.Body.String(), "do-not-leak") || !strings.Contains(recorder.Body.String(), `"status":"not_ready"`) {
		t.Fatalf("readiness body = %s", recorder.Body.String())
	}
}

func TestReadinessSucceedsWhenEveryCheckPasses(t *testing.T) {
	t.Parallel()
	server := &Server{cfg: &config.Config{Server: config.ServerConfig{ReadinessTimeout: time.Second}}}
	server.readiness.checks = []readinessCheck{
		{name: "database", check: func(context.Context) error { return nil }},
		{name: "redis", check: func(context.Context) error { return nil }},
	}
	recorder := httptest.NewRecorder()
	server.handleReadiness(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"ready"`) {
		t.Fatalf("readiness response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestReadinessIgnoresIntentionalServiceControlPauses(t *testing.T) {
	t.Parallel()
	server := &Server{
		cfg: &config.Config{Server: config.ServerConfig{ReadinessTimeout: time.Second}},
		serviceControl: &fakeServiceControlRuntime{snapshot: servicecontrol.Snapshot{
			PausedCapabilities: servicecontrol.AllCapabilities(),
		}},
	}
	server.readiness.checks = []readinessCheck{
		{name: "database", check: func(context.Context) error { return nil }},
		{name: "redis", check: func(context.Context) error { return nil }},
	}
	recorder := httptest.NewRecorder()
	server.handleReadiness(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"ready"`) {
		t.Fatalf("readiness during full pause = %d %s", recorder.Code, recorder.Body.String())
	}
}
