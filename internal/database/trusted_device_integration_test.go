package database_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/trusteddevice"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestTrustedDeviceTokenLifecycleAndAuthenticationBinding(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run trusted device migrations: %v", err)
	}
	ctx := context.Background()
	current := registrationTestUser("trusted-device-user", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, current)
	store := trusteddevice.NewStore(schema.pool)
	mutation := audit.MutationAudit{
		Event: models.AuditTrustedDeviceCreated, ActorID: current.ID, ActorName: current.Username,
		Result: "success", RiskLevel: "medium", IPAddress: "192.0.2.20", UserAgent: "integration-browser",
	}
	device, token, err := store.Issue(ctx, current, mutation.IPAddress, mutation.UserAgent, 30*24*time.Hour, uuid.Nil, mutation)
	if err != nil {
		t.Fatal(err)
	}
	var storedHash []byte
	if err := schema.pool.QueryRow(ctx, `SELECT token_hash FROM user_trusted_devices WHERE id=$1`, device.ID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if len(storedHash) != 32 || string(storedHash) == token.Secret {
		t.Fatalf("stored token material is invalid: length=%d", len(storedHash))
	}

	now := time.Now().UTC()
	valid, err := store.ValidateAndTouch(ctx, token, current, 30*24*time.Hour, "192.0.2.21", "updated-browser", now)
	if err != nil || !valid {
		t.Fatalf("valid token accepted=%v err=%v", valid, err)
	}
	wrong := token
	wrong.Secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	valid, err = store.ValidateAndTouch(ctx, wrong, current, 30*24*time.Hour, "", "", now)
	if err != nil || valid {
		t.Fatalf("wrong token accepted=%v err=%v", valid, err)
	}
	changed := *current
	changed.AuthVersion++
	valid, err = store.ValidateAndTouch(ctx, token, &changed, 30*24*time.Hour, "", "", now)
	if err != nil || valid {
		t.Fatalf("token with changed auth version accepted=%v err=%v", valid, err)
	}

	items, err := store.List(ctx, current, 7*24*time.Hour, token.ID)
	if err != nil || len(items) != 1 || !items[0].Current || items[0].ExpiresAt.After(items[0].CreatedAt.Add(7*24*time.Hour+time.Second)) {
		t.Fatalf("effective trusted devices = %#v err=%v", items, err)
	}
	revoke := mutation
	revoke.Event = models.AuditTrustedDeviceRevoked
	if err := store.Revoke(ctx, current.ID, token.ID, revoke); err != nil {
		t.Fatal(err)
	}
	valid, err = store.ValidateAndTouch(ctx, token, current, 30*24*time.Hour, "", "", now)
	if err != nil || valid {
		t.Fatalf("revoked token accepted=%v err=%v", valid, err)
	}
}

func TestLoginHistoryExcludesReauthenticationAndUnrelatedAuditEvents(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run login history migrations: %v", err)
	}
	ctx := context.Background()
	current := registrationTestUser("login-history-user", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, current)
	store := audit.NewStore(schema.pool)
	actorID := current.ID
	actorName := current.Username
	ip := "198.51.100.40"
	userAgent := "history-browser"
	now := time.Now().UTC()
	events := []*models.AuditLog{
		{ID: uuid.New(), Event: models.AuditUserLogin, ActorID: &actorID, ActorName: &actorName, Result: "success", RiskLevel: "low", IPAddress: &ip, UserAgent: &userAgent, Details: map[string]any{"authentication_method": "password", "secret": "must-not-be-projected"}, CreatedAt: now},
		{ID: uuid.New(), Event: models.AuditUserLoginFailed, ActorID: &actorID, ActorName: &actorName, Result: "failure", RiskLevel: "medium", Details: map[string]any{"authentication_method": "password"}, CreatedAt: now.Add(-time.Second)},
		{ID: uuid.New(), Event: models.AuditMFAChallengeFailed, ActorID: &actorID, ActorName: &actorName, Result: "failure", RiskLevel: "medium", Details: map[string]any{"purpose": "login", "primary_method": "password", "mfa_method": "totp"}, CreatedAt: now.Add(-2 * time.Second)},
		{ID: uuid.New(), Event: models.AuditMFAChallengeFailed, ActorID: &actorID, ActorName: &actorName, Result: "failure", RiskLevel: "medium", Details: map[string]any{"purpose": "reauthentication", "mfa_method": "totp"}, CreatedAt: now.Add(-3 * time.Second)},
		{ID: uuid.New(), Event: models.AuditUserLoginFailed, ActorID: &actorID, ActorName: &actorName, Result: "failure", RiskLevel: "medium", Details: map[string]any{"purpose": "mfa_reauthentication", "authentication_method": "passkey"}, CreatedAt: now.Add(-4 * time.Second)},
		{ID: uuid.New(), Event: models.AuditUserUpdated, ActorID: &actorID, ActorName: &actorName, Result: "success", RiskLevel: "low", Details: map[string]any{}, CreatedAt: now.Add(-5 * time.Second)},
	}
	for _, event := range events {
		if err := store.Record(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	history, err := store.ListLoginHistory(ctx, current.ID, 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	if history.Total != 3 || len(history.Items) != 3 {
		t.Fatalf("login history = %#v, want three login events", history)
	}
	if history.Items[0].AuthenticationMethod != "password" || history.Items[2].SecondFactor != "totp" {
		t.Fatalf("projected login history = %#v", history.Items)
	}
}
