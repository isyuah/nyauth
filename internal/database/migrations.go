package database

import (
	"context"
	"errors"
	"fmt"

	migrate "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	migrationfiles "github.com/nyasharp/nyauth/migrations"
)

const SchemaVersion int64 = 1

func RunMigrations(databaseURL string) error {
	source, err := iofs.New(migrationfiles.Files, ".")
	if err != nil {
		return fmt.Errorf("opening embedded migrations: %w", err)
	}
	runner, err := migrate.NewWithSourceInstance("iofs", source, databaseURL)
	if err != nil {
		_ = source.Close()
		return fmt.Errorf("creating migration runner: %w", err)
	}
	migrationErr := runner.Up()
	if errors.Is(migrationErr, migrate.ErrNoChange) {
		migrationErr = nil
	}
	sourceErr, databaseErr := runner.Close()
	if migrationErr != nil {
		return fmt.Errorf("applying migrations: %w", migrationErr)
	}
	if closeErr := errors.Join(sourceErr, databaseErr); closeErr != nil {
		return fmt.Errorf("closing migration runner: %w", closeErr)
	}
	return nil
}

func ValidateSchemaVersion(ctx context.Context, pool *pgxpool.Pool) error {
	var version int64
	var dirty bool
	var rows int64
	err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version),0), COALESCE(BOOL_OR(dirty),FALSE), COUNT(*) FROM schema_migrations`).Scan(&version, &dirty, &rows)
	if err != nil {
		return fmt.Errorf("reading schema version (run `nyauth migrate` first): %w", err)
	}
	return validateSchemaState(version, dirty, rows)
}

func validateSchemaState(version int64, dirty bool, rows int64) error {
	if rows != 1 {
		return fmt.Errorf("invalid schema migration history: expected one baseline version row, found %d", rows)
	}
	if dirty {
		return fmt.Errorf("database schema version %d is dirty", version)
	}
	if version != SchemaVersion {
		return fmt.Errorf("database schema version %d is incompatible with required version %d", version, SchemaVersion)
	}
	return nil
}
