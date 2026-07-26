package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	nyauthroot "github.com/nyasharp/nyauth"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/recovery"
	"github.com/nyasharp/nyauth/internal/registration"
	"github.com/nyasharp/nyauth/internal/server"
	"github.com/nyasharp/nyauth/internal/telemetry"
)

const (
	commandServe          = "serve"
	commandMigrate        = "migrate"
	commandMaintenance    = "maintenance"
	commandHealthcheck    = "healthcheck"
	commandVerifyRecovery = "verify-recovery"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).With(
		"service", "nyauth",
		"version", version,
		"commit", commit,
	)
	slog.SetDefault(logger)
	command, args, err := parseCommand(os.Args[1:])
	if err != nil {
		fatal("parsing command", err)
	}
	if command == commandHealthcheck {
		if err := runHealthcheck(args); err != nil {
			fatal("healthcheck failed", err)
		}
		return
	}
	flags := flag.NewFlagSet("nyauth "+command, flag.ExitOnError)
	configPath := flags.String("config", "", "path to config file (default: config.yaml)")
	if err := flags.Parse(args); err != nil {
		fatal("parsing arguments", err)
	}
	if flags.NArg() != 0 {
		fatal("parsing arguments", fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " ")))
	}
	cfg, err := loadCommandConfig(command, *configPath)
	if err != nil {
		fatal("loading config", err)
	}
	if command == commandMigrate {
		if err := database.RunConfiguredMigrations(cfg.Database); err != nil {
			fatal("running migrations", err)
		}
		if err := ensureRuntimePrivileges(cfg); err != nil {
			fatal("granting runtime database privileges", err)
		}
		slog.Info("migrations applied successfully")
		if err := runAuditMaintenance(cfg); err != nil {
			fatal("maintaining audit storage", err)
		}
		return
	}
	if command == commandMaintenance {
		if err := runAuditMaintenance(cfg); err != nil {
			fatal("maintaining audit storage", err)
		}
		return
	}
	if command == commandVerifyRecovery {
		if err := runRecoveryVerification(cfg); err != nil {
			fatal("verifying recovered state", err)
		}
		return
	}
	ctx := context.Background()
	db, err := database.NewPostgresPool(ctx, cfg.Database)
	if err != nil {
		fatal("connecting to database", err)
	}
	defer db.Close()
	if cfg.IsProduction() {
		if err := database.ValidateRuntimeRole(ctx, db, cfg.Database.RuntimeRole); err != nil {
			fatal("validating runtime database role", err)
		}
	}
	if err := database.ValidateSchemaVersion(ctx, db); err != nil {
		fatal("validating database schema", err)
	}
	rdb, err := database.NewRedisClient(cfg.Redis)
	if err != nil {
		fatal("configuring redis", err)
	}
	defer rdb.Close()
	redisContext, cancelRedis := context.WithTimeout(ctx, cfg.Redis.DialTimeout+cfg.Redis.ReadTimeout)
	defer cancelRedis()
	if err := rdb.Ping(redisContext).Err(); err != nil {
		fatal("connecting to redis", err)
	}
	telemetryRuntime, err := telemetry.New(ctx, telemetry.Options{
		OTLPEnabled:        cfg.Telemetry.OTLP.Enabled,
		OTLPEndpoint:       cfg.Telemetry.OTLP.Endpoint,
		OTLPAuthorization:  cfg.Telemetry.OTLP.Authorization,
		OTLPExportInterval: cfg.Telemetry.OTLP.ExportInterval,
		OTLPTimeout:        cfg.Telemetry.OTLP.Timeout,
	})
	if err != nil {
		fatal("initializing telemetry", err)
	}
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := telemetryRuntime.Shutdown(shutdownContext); shutdownErr != nil {
			slog.Warn("telemetry shutdown failed", "error", shutdownErr)
		}
	}()
	srv, err := server.New(cfg, db, rdb, nyauthroot.WebFS, telemetryRuntime)
	if err != nil {
		fatal("initializing server", err)
	}
	if err := srv.Run(ctx); err != nil {
		fatal("server stopped with an error", err)
	}
}

func ensureRuntimePrivileges(cfg *config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := database.NewPostgresPool(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("connecting with the migration account: %w", err)
	}
	defer db.Close()
	return database.EnsureRuntimePrivileges(ctx, db, cfg.Database.RuntimeRole)
}

func loadCommandConfig(command, path string) (*config.Config, error) {
	if command == commandMigrate || command == commandMaintenance {
		return config.LoadDatabaseMaintenance(path)
	}
	return config.Load(path)
}

func fatal(message string, err error) {
	slog.Error(message, "error", err)
	os.Exit(1)
}

func runAuditMaintenance(cfg *config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db, err := database.NewPostgresPool(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("connecting with the migration account: %w", err)
	}
	defer db.Close()
	if err := database.ValidateSchemaVersion(ctx, db); err != nil {
		return fmt.Errorf("validating schema before audit maintenance: %w", err)
	}
	store := audit.NewStore(db)
	now := time.Now().UTC()
	if err := store.EnsureMonthlyPartitions(ctx, now, 18); err != nil {
		return err
	}
	retention, err := store.ApplyRetention(ctx, now.Add(-cfg.Audit.Retention))
	if err != nil {
		return err
	}
	cleanedOutbox, err := store.CleanupProcessedOutbox(ctx, now.Add(-7*24*time.Hour), 50_000)
	if err != nil {
		return err
	}
	registrationCleanup, err := registration.NewStore(db).CleanupExpired(ctx, now, 500, 100)
	if err != nil {
		return err
	}
	slog.Info("audit storage maintenance completed",
		"dropped_partitions", retention.DroppedPartitions,
		"deleted_boundary_rows", retention.DeletedRows,
		"deleted_processed_outbox_rows", cleanedOutbox,
		"released_pending_registrations", registrationCleanup.Released,
		"deleted_pending_users", registrationCleanup.DeletedUsers,
	)
	return nil
}

func runRecoveryVerification(cfg *config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db, err := database.NewPostgresPool(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("connecting to recovered database: %w", err)
	}
	defer db.Close()
	report, err := recovery.Verify(ctx, db, cfg.Auth.MasterKey)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return fmt.Errorf("encoding recovery verification report: %w", err)
	}
	return nil
}

func runHealthcheck(args []string) error {
	flags := flag.NewFlagSet("nyauth healthcheck", flag.ContinueOnError)
	target := flags.String("url", "http://127.0.0.1:8080/readyz", "readiness endpoint URL")
	timeout := flags.Duration("timeout", 3*time.Second, "healthcheck timeout")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parsing healthcheck arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected healthcheck arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *timeout <= 0 {
		return fmt.Errorf("healthcheck timeout must be positive")
	}
	parsedTarget, err := url.Parse(*target)
	if err != nil || parsedTarget.Host == "" || (parsedTarget.Scheme != "http" && parsedTarget.Scheme != "https") || parsedTarget.User != nil || parsedTarget.RawQuery != "" || parsedTarget.Fragment != "" {
		return fmt.Errorf("healthcheck URL must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	client := &http.Client{Timeout: *timeout}
	request, err := http.NewRequest(http.MethodGet, parsedTarget.String(), nil)
	if err != nil {
		return fmt.Errorf("creating healthcheck request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("requesting readiness endpoint: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("readiness endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}

func parseCommand(args []string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return commandServe, args, nil
	}
	switch args[0] {
	case commandServe, commandMigrate, commandMaintenance, commandHealthcheck, commandVerifyRecovery:
		return args[0], args[1:], nil
	default:
		return "", nil, fmt.Errorf("unknown command %q (expected serve, migrate, maintenance, healthcheck, or verify-recovery)", args[0])
	}
}
