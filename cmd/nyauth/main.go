package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	nyauthroot "github.com/nyasharp/nyauth"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/avatar"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/humanverification"
	"github.com/nyasharp/nyauth/internal/mfa"
	"github.com/nyasharp/nyauth/internal/oauthops"
	"github.com/nyasharp/nyauth/internal/provider"
	"github.com/nyasharp/nyauth/internal/recovery"
	"github.com/nyasharp/nyauth/internal/registration"
	"github.com/nyasharp/nyauth/internal/server"
	"github.com/nyasharp/nyauth/internal/servicecontrol"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/internal/telemetry"
)

const (
	commandServe             = "serve"
	commandMigrate           = "migrate"
	commandMaintenance       = "maintenance"
	commandHealthcheck       = "healthcheck"
	commandVerifyRecovery    = "verify-recovery"
	commandServiceControl    = "service-control"
	commandMFA               = "mfa"
	commandHumanVerification = "human-verification"
)

var (
	version = "0.7.0-dev"
	commit  = "unknown"
)

func main() {
	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelInfo)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})).With(
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
	if command == commandServiceControl {
		if err := runServiceControl(args); err != nil {
			fatal("service control failed", err)
		}
		return
	}
	if command == commandMFA {
		if err := runMFA(args); err != nil {
			fatal("MFA recovery failed", err)
		}
		return
	}
	if command == commandHumanVerification {
		if err := runHumanVerification(args); err != nil {
			fatal("human verification recovery failed", err)
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
		if err := runAuditMaintenance(cfg, false); err != nil {
			fatal("maintaining audit storage", err)
		}
		return
	}
	if command == commandMaintenance {
		if err := runAuditMaintenance(cfg, true); err != nil {
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
		LogLevel:           logLevel,
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
	if command == commandMigrate {
		return config.LoadDatabaseMaintenance(path)
	}
	if command == commandMaintenance {
		return config.LoadMaintenance(path)
	}
	return config.Load(path)
}

func fatal(message string, err error) {
	slog.Error(message, "error", err)
	os.Exit(1)
}

func runAuditMaintenance(cfg *config.Config, includeAvatarMedia bool) error {
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
	retentionDuration, err := settings.ResolveAuditRetention(ctx, db, cfg.Audit.Retention)
	if err != nil {
		return err
	}
	retention, err := store.ApplyRetention(ctx, now.Add(-retentionDuration))
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
	oauthDiagnostics, oauthDaily, err := oauthops.NewStore(db).Cleanup(ctx, now)
	if err != nil {
		return err
	}
	providerDiagnostics, err := provider.CleanupDiagnosticRuns(ctx, db, now.Add(-90*24*time.Hour))
	if err != nil {
		return err
	}
	var cleanedAvatarRows int64
	if includeAvatarMedia {
		var mediaStore avatar.BlobStore
		switch cfg.Media.Backend {
		case "local":
			mediaStore, err = avatar.NewLocalStore(cfg.Media.Local.Directory)
		case "s3":
			mediaStore, err = avatar.NewS3Store(ctx, cfg.Media.S3)
		}
		if err != nil {
			return fmt.Errorf("configuring avatar media maintenance: %w", err)
		}
		avatarRepository := avatar.NewRepository(db)
		if err := avatarRepository.EnsureStorageBackendCompatible(ctx, mediaStore.Backend()); err != nil {
			return fmt.Errorf("validating avatar media maintenance storage: %w", err)
		}
		avatarService, serviceErr := avatar.NewService(avatarRepository, mediaStore, avatar.NewProcessor())
		if serviceErr != nil {
			return serviceErr
		}
		avatarCleanup, cleanupErr := avatarService.Cleanup(ctx, now, 15*time.Minute, 500, 100)
		if cleanupErr != nil {
			return cleanupErr
		}
		cleanedAvatarRows = avatarCleanup.Rows
	}
	slog.Info("audit storage maintenance completed",
		"dropped_partitions", retention.DroppedPartitions,
		"deleted_boundary_rows", retention.DeletedRows,
		"deleted_processed_outbox_rows", cleanedOutbox,
		"released_pending_registrations", registrationCleanup.Released,
		"deleted_pending_users", registrationCleanup.DeletedUsers,
		"deleted_oauth_diagnostics", oauthDiagnostics,
		"deleted_oauth_daily_statistics", oauthDaily,
		"deleted_provider_diagnostics", providerDiagnostics,
		"cleaned_avatar_rows", cleanedAvatarRows,
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

type serviceControlResetReport struct {
	Revision          int64                     `json:"revision"`
	ApplicationStatus string                    `json:"application_status"`
	ActiveInstances   int                       `json:"active_instances"`
	AppliedInstances  int                       `json:"applied_instances"`
	Instances         []servicecontrol.Instance `json:"instances"`
}

func runServiceControl(args []string) error {
	if len(args) == 0 || args[0] != "reset" {
		return fmt.Errorf("expected `service-control reset`")
	}
	flags := flag.NewFlagSet("nyauth service-control reset", flag.ContinueOnError)
	configPath := flags.String("config", "", "path to config file (default: config.yaml)")
	reason := flags.String("reason", "", "mandatory break-glass reset reason")
	waitTimeout := flags.Duration("wait", 30*time.Second, "maximum time to wait for active instances")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("parsing service control reset arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected service control arguments: %s", strings.Join(flags.Args(), " "))
	}
	if strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("service-control reset requires -reason")
	}
	if *waitTimeout <= 0 || *waitTimeout > 5*time.Minute {
		return fmt.Errorf("service-control reset wait must be greater than zero and no more than 5m")
	}
	cfg, err := config.LoadDatabaseMaintenance(*configPath)
	if err != nil {
		return fmt.Errorf("loading database configuration: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	db, err := database.NewPostgresPool(ctx, cfg.Database)
	cancel()
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer db.Close()
	validationCtx, cancelValidation := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelValidation()
	if err := database.ValidateSchemaVersion(validationCtx, db); err != nil {
		return fmt.Errorf("validating database schema: %w", err)
	}
	store, err := servicecontrol.NewStore(db)
	if err != nil {
		return err
	}
	resetCtx, cancelReset := context.WithTimeout(context.Background(), 30*time.Second)
	snapshot, err := store.Reset(resetCtx, servicecontrol.ResetInput{
		Reason: *reason, ActorName: "nyauth service-control CLI",
	})
	cancelReset()
	if err != nil {
		return err
	}
	waitCtx, cancelWait := context.WithTimeout(context.Background(), *waitTimeout)
	status, waitErr := store.WaitForApplied(waitCtx, snapshot.Revision, servicecontrol.DefaultStaleAfter)
	cancelWait()
	if waitErr != nil && !errors.Is(waitErr, context.DeadlineExceeded) && !errors.Is(waitErr, context.Canceled) {
		return fmt.Errorf("waiting for service control application: %w", waitErr)
	}
	applicationStatus := "applying"
	if status.Applied {
		applicationStatus = "applied"
	}
	report := serviceControlResetReport{
		Revision: snapshot.Revision, ApplicationStatus: applicationStatus,
		ActiveInstances: status.ActiveInstances, AppliedInstances: status.AppliedInstances,
		Instances: status.Instances,
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return fmt.Errorf("encoding service control reset report: %w", err)
	}
	return nil
}

func runMFA(args []string) error {
	if len(args) == 0 || args[0] != "reset" {
		return fmt.Errorf("expected `mfa reset`")
	}
	flags := flag.NewFlagSet("nyauth mfa reset", flag.ContinueOnError)
	configPath := flags.String("config", "", "path to config file (default: config.yaml)")
	userIDValue := flags.String("user-id", "", "exact target user UUID")
	username := flags.String("username", "", "exact target username")
	scopeValue := flags.String("scope", string(mfa.RecoveryResetAll), "factors to reset: all, totp, or passkeys")
	reason := flags.String("reason", "", "mandatory break-glass recovery reason")
	confirmation := flags.String("confirm", "", "repeat the exact username or user UUID")
	disableAdminRequirement := flags.Bool("disable-admin-mfa-requirement", false, "also disable mandatory administrator MFA when required for recovery")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("parsing MFA reset arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected MFA reset arguments: %s", strings.Join(flags.Args(), " "))
	}
	userIDText := strings.TrimSpace(*userIDValue)
	usernameText := strings.TrimSpace(*username)
	if (userIDText == "") == (usernameText == "") {
		return fmt.Errorf("mfa reset requires exactly one of -user-id or -username")
	}
	targetConfirmation := usernameText
	var userID uuid.UUID
	if userIDText != "" {
		parsed, err := uuid.Parse(userIDText)
		if err != nil {
			return fmt.Errorf("mfa reset user ID is invalid")
		}
		userID = parsed
		targetConfirmation = parsed.String()
	}
	if strings.TrimSpace(*confirmation) != targetConfirmation {
		return fmt.Errorf("mfa reset -confirm must exactly match the selected username or canonical user UUID")
	}
	scope, err := mfa.ParseRecoveryResetScope(*scopeValue)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(*reason)) < 3 || len(strings.TrimSpace(*reason)) > 500 {
		return fmt.Errorf("mfa reset requires a reason containing 3 to 500 characters")
	}
	cfg, err := config.LoadDatabaseMaintenance(*configPath)
	if err != nil {
		return fmt.Errorf("loading database configuration: %w", err)
	}
	connectCtx, cancelConnect := context.WithTimeout(context.Background(), 30*time.Second)
	db, err := database.NewPostgresPool(connectCtx, cfg.Database)
	cancelConnect()
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer db.Close()
	validationCtx, cancelValidation := context.WithTimeout(context.Background(), 30*time.Second)
	if err := database.ValidateSchemaVersion(validationCtx, db); err != nil {
		cancelValidation()
		return fmt.Errorf("validating database schema: %w", err)
	}
	cancelValidation()
	resetCtx, cancelReset := context.WithTimeout(context.Background(), 30*time.Second)
	report, err := mfa.ResetForRecovery(resetCtx, db, mfa.RecoveryResetInput{
		UserID: userID, Username: usernameText, Scope: scope,
		Reason: *reason, DisableAdminMFARequirement: *disableAdminRequirement,
		ActorName: "nyauth mfa CLI", Now: time.Now().UTC(),
	})
	cancelReset()
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return fmt.Errorf("encoding MFA reset report: %w", err)
	}
	return nil
}

func runHumanVerification(args []string) error {
	if len(args) == 0 || args[0] != "disable" {
		return fmt.Errorf("expected `human-verification disable`")
	}
	flags := flag.NewFlagSet("nyauth human-verification disable", flag.ContinueOnError)
	configPath := flags.String("config", "", "path to config file (default: config.yaml)")
	reason := flags.String("reason", "", "mandatory break-glass disable reason")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("parsing human verification arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected human verification arguments: %s", strings.Join(flags.Args(), " "))
	}
	normalizedReason, err := humanverification.NormalizeRecoveryReason(*reason)
	if err != nil {
		return err
	}
	cfg, err := config.LoadDatabaseMaintenance(*configPath)
	if err != nil {
		return fmt.Errorf("loading database configuration: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := database.NewPostgresPool(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer db.Close()
	if err := database.ValidateSchemaVersion(ctx, db); err != nil {
		return fmt.Errorf("validating database schema: %w", err)
	}
	report, err := humanverification.DisableForRecovery(ctx, db, normalizedReason, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return fmt.Errorf("encoding human verification recovery report: %w", err)
	}
	return nil
}

func parseCommand(args []string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return commandServe, args, nil
	}
	switch args[0] {
	case commandServe, commandMigrate, commandMaintenance, commandHealthcheck, commandVerifyRecovery, commandServiceControl, commandMFA, commandHumanVerification:
		return args[0], args[1:], nil
	default:
		return "", nil, fmt.Errorf("unknown command %q (expected serve, migrate, maintenance, healthcheck, verify-recovery, service-control, mfa, or human-verification)", args[0])
	}
}
