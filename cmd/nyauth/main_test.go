package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunHealthcheck(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	if err := runHealthcheck([]string{"-url", server.URL, "-timeout", "1s"}); err != nil {
		t.Fatalf("runHealthcheck() error = %v", err)
	}
}

func TestRunHealthcheckRejectsNotReady(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	err := runHealthcheck([]string{"-url", server.URL})
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("runHealthcheck() error = %v", err)
	}
}

func TestRunHealthcheckRejectsSensitiveURLComponents(t *testing.T) {
	t.Parallel()
	err := runHealthcheck([]string{"-url", "http://user:secret@127.0.0.1:8080/readyz?token=secret"})
	if err == nil || strings.Contains(err.Error(), "user:secret") || !strings.Contains(err.Error(), "without credentials") {
		t.Fatalf("runHealthcheck() error = %v", err)
	}
}

func TestParseCommand(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		command string
		rest    []string
		wantErr bool
	}{
		{name: "default serve", command: commandServe},
		{name: "flags serve", args: []string{"-config", "config.yaml"}, command: commandServe, rest: []string{"-config", "config.yaml"}},
		{name: "explicit serve", args: []string{"serve", "-config", "config.yaml"}, command: commandServe, rest: []string{"-config", "config.yaml"}},
		{name: "migrate", args: []string{"migrate", "-config", "config.yaml"}, command: commandMigrate, rest: []string{"-config", "config.yaml"}},
		{name: "maintenance", args: []string{"maintenance", "-config", "config.yaml"}, command: commandMaintenance, rest: []string{"-config", "config.yaml"}},
		{name: "healthcheck", args: []string{"healthcheck", "-timeout", "1s"}, command: commandHealthcheck, rest: []string{"-timeout", "1s"}},
		{name: "verify recovery", args: []string{"verify-recovery", "-config", "config.yaml"}, command: commandVerifyRecovery, rest: []string{"-config", "config.yaml"}},
		{name: "unknown", args: []string{"rollback"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, rest, err := parseCommand(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v", err)
			}
			if got != tt.command {
				t.Errorf("command = %q, want %q", got, tt.command)
			}
			if len(rest) != len(tt.rest) {
				t.Fatalf("rest = %#v, want %#v", rest, tt.rest)
			}
			for i := range rest {
				if rest[i] != tt.rest[i] {
					t.Errorf("rest[%d] = %q, want %q", i, rest[i], tt.rest[i])
				}
			}
		})
	}
}

func TestLoadCommandConfigUsesDatabaseMaintenanceScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
database:
  driver: postgres
  dsn: postgres://migrator@postgres.internal/nyauth
auth:
  issuer: invalid
  master_key: invalid
admin:
  password: must-not-be-read
`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{commandMigrate, commandMaintenance} {
		if _, err := loadCommandConfig(command, path); err != nil {
			t.Fatalf("loadCommandConfig(%q) error = %v", command, err)
		}
	}
	if _, err := loadCommandConfig(commandServe, path); err == nil {
		t.Fatal("loadCommandConfig(serve) unexpectedly skipped full validation")
	}
}
