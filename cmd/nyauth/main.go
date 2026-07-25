package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	nyauthroot "github.com/nyasharp/nyauth"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/server"
)

const (
	commandServe   = "serve"
	commandMigrate = "migrate"
)

func main() {
	command, args, err := parseCommand(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	flags := flag.NewFlagSet("nyauth "+command, flag.ExitOnError)
	configPath := flags.String("config", "", "path to config file (default: config.yaml)")
	if err := flags.Parse(args); err != nil {
		log.Fatalf("parsing arguments: %v", err)
	}
	if flags.NArg() != 0 {
		log.Fatalf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}
	if command == commandMigrate {
		if err := database.RunMigrations(cfg.Database.DSN); err != nil {
			log.Fatalf("running migrations: %v", err)
		}
		fmt.Println("migrations applied successfully")
		return
	}
	ctx := context.Background()
	db, err := database.NewPostgresPool(ctx, cfg.Database.DSN)
	if err != nil {
		log.Fatalf("connecting to database: %v", err)
	}
	defer db.Close()
	if err := database.ValidateSchemaVersion(ctx, db); err != nil {
		log.Fatalf("validating database schema: %v", err)
	}
	rdb := database.NewRedisClient(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB)
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("connecting to redis: %v", err)
	}
	srv := server.New(cfg, db, rdb, nyauthroot.WebFS)
	if err := srv.Run(ctx); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func parseCommand(args []string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return commandServe, args, nil
	}
	switch args[0] {
	case commandServe, commandMigrate:
		return args[0], args[1:], nil
	default:
		return "", nil, fmt.Errorf("unknown command %q (expected serve or migrate)", args[0])
	}
}
