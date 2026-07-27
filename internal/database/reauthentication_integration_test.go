package database_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestRecordAuthenticationRejectsStaleSecurityVersions(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	ctx := context.Background()
	store := user.NewStore(schema.pool)

	tests := []struct {
		name     string
		username string
		advance  string
	}{
		{name: "authentication version", username: "stale-reauth-auth", advance: "auth_version=auth_version+1"},
		{name: "session version", username: "stale-reauth-session", advance: "session_version=session_version+1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := registrationTestUser(test.username, models.UserStatusActive)
			if err := store.Create(ctx, current); err != nil {
				t.Fatal(err)
			}
			if _, err := schema.pool.Exec(ctx, "UPDATE users SET "+test.advance+" WHERE id=$1", current.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := store.RecordAuthentication(ctx, current.ID, 1, 1); !errors.Is(err, user.ErrAuthStateChanged) {
				t.Fatalf("stale reauthentication error=%v", err)
			}
			var lastAuthenticatedAt *time.Time
			if err := schema.pool.QueryRow(ctx, `
				SELECT last_authenticated_at FROM users WHERE id=$1
			`, current.ID).Scan(&lastAuthenticatedAt); err != nil {
				t.Fatal(err)
			}
			if lastAuthenticatedAt != nil {
				t.Fatalf("stale reauthentication changed timestamp to %v", *lastAuthenticatedAt)
			}
		})
	}
}
