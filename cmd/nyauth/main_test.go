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
		{name: "service control reset", args: []string{"service-control", "reset", "-reason", "incident resolved"}, command: commandServiceControl, rest: []string{"reset", "-reason", "incident resolved"}},
		{name: "MFA reset", args: []string{"mfa", "reset", "-username", "admin"}, command: commandMFA, rest: []string{"reset", "-username", "admin"}},
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

func TestRunMFARejectsInvalidArgumentsBeforeLoadingConfiguration(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing subcommand", want: "mfa reset"},
		{name: "unknown subcommand", args: []string{"status"}, want: "mfa reset"},
		{name: "missing selector", args: []string{"reset", "-reason", "lost device"}, want: "exactly one"},
		{name: "multiple selectors", args: []string{"reset", "-username", "admin", "-user-id", "967ba07e-9c8e-4a76-8360-3470b10792b7", "-reason", "lost device"}, want: "exactly one"},
		{name: "invalid UUID", args: []string{"reset", "-user-id", "invalid", "-reason", "lost device", "-confirm", "invalid"}, want: "user ID is invalid"},
		{name: "missing confirmation", args: []string{"reset", "-username", "admin", "-reason", "lost device"}, want: "-confirm"},
		{name: "wrong confirmation", args: []string{"reset", "-username", "admin", "-reason", "lost device", "-confirm", "other"}, want: "-confirm"},
		{name: "invalid scope", args: []string{"reset", "-username", "admin", "-reason", "lost device", "-confirm", "admin", "-scope", "recovery"}, want: "all, totp, or passkeys"},
		{name: "short reason", args: []string{"reset", "-username", "admin", "-reason", "x", "-confirm", "admin"}, want: "3 to 500"},
		{name: "unexpected argument", args: []string{"reset", "-username", "admin", "-reason", "lost device", "-confirm", "admin", "extra"}, want: "unexpected MFA reset arguments"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := runMFA(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("runMFA(%v) error = %v, want containing %q", test.args, err, test.want)
			}
		})
	}
}

func TestRunServiceControlRejectsInvalidArgumentsBeforeLoadingConfiguration(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing subcommand", want: "service-control reset"},
		{name: "unknown subcommand", args: []string{"status"}, want: "service-control reset"},
		{name: "missing reason", args: []string{"reset"}, want: "requires -reason"},
		{name: "blank reason", args: []string{"reset", "-reason", "   "}, want: "requires -reason"},
		{name: "unexpected argument", args: []string{"reset", "-reason", "incident resolved", "extra"}, want: "unexpected service control arguments"},
		{name: "zero wait", args: []string{"reset", "-reason", "incident resolved", "-wait", "0s"}, want: "greater than zero"},
		{name: "excessive wait", args: []string{"reset", "-reason", "incident resolved", "-wait", "6m"}, want: "no more than 5m"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := runServiceControl(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("runServiceControl(%v) error = %v, want containing %q", test.args, err, test.want)
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
