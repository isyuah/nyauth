package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/server"
	nyauthroot "github.com/nyasharp/nyauth"
)

func main() {
	configPath := flag.String("config", "", "path to config file (default: config.yaml)")
	migrateFlag := flag.Bool("migrate", false, "run database migrations then exit")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	ctx := context.Background()

	// Connect to PostgreSQL
	db, err := database.NewPostgresPool(ctx, cfg.Database.DSN)
	if err != nil {
		log.Fatalf("connecting to database: %v", err)
	}
	defer db.Close()

	// Run migrations if requested
	if *migrateFlag {
		if err := runMigrations(db); err != nil {
			log.Fatalf("running migrations: %v", err)
		}
		fmt.Println("migrations applied successfully")
		os.Exit(0)
	}

	// Connect to Redis
	rdb := database.NewRedisClient(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB)
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("connecting to redis: %v", err)
	}

	// Create and run server
	srv := server.New(cfg, db, rdb, nyauthroot.WebFS)
	if err := srv.Run(ctx); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func runMigrations(db *pgxpool.Pool) error {
	ctx := context.Background()

	_, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version BIGINT PRIMARY KEY,
			dirty BOOLEAN NOT NULL DEFAULT FALSE
		)
	`)
	if err != nil {
		return fmt.Errorf("creating migrations table: %w", err)
	}

	migrations := map[string]string{
		"000001": "init_users",
		"000002": "init_clients",
		"000003": "init_providers",
		"000004": "init_identities",
		"000005": "init_jwk_keys",
		"000006": "add_audit_logs",
		"000007": "add_user_fields",
		"000008": "add_client_owner",
	}

	for version, name := range migrations {
		var exists bool
		err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&exists)
		if err != nil {
			return fmt.Errorf("checking migration %s: %w", version, err)
		}
		if exists {
			continue
		}

		migrationSQL, err := os.ReadFile(fmt.Sprintf("migrations/%s_%s.up.sql", version, name))
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", version, err)
		}

		tx, err := db.Begin(ctx)
		if err != nil {
			return fmt.Errorf("beginning transaction for %s: %w", version, err)
		}

		if _, err := tx.Exec(ctx, string(migrationSQL)); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("executing migration %s: %w", version, err)
		}

		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, dirty) VALUES ($1, FALSE)`, version); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("recording migration %s: %w", version, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("committing migration %s: %w", version, err)
		}

		fmt.Printf("applied migration %s_%s\n", version, name)
	}

	return nil
}
