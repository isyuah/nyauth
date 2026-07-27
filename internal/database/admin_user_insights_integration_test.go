package database_test

import (
	"context"
	"testing"
	"time"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/identity"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	"github.com/nyasharp/nyauth/internal/user"
	migrationfiles "github.com/nyasharp/nyauth/migrations"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestAdminUserInsightsMigrationBackfillsOnlyAuthoritativeRegistrations(t *testing.T) {
	schema := newPostgresTestSchema(t)
	source, err := iofs.New(migrationfiles.Files, ".")
	if err != nil {
		t.Fatalf("open embedded migrations: %v", err)
	}
	runner, err := migrate.NewWithSourceInstance("iofs", source, schema.migrationDSN)
	if err != nil {
		_ = source.Close()
		t.Fatalf("create migration runner: %v", err)
	}
	t.Cleanup(func() { _, _ = runner.Close() })
	if err := runner.Migrate(9); err != nil {
		t.Fatalf("migrate to avatar schema: %v", err)
	}

	ctx := context.Background()
	legacyID := uuid.New()
	registeredID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,metadata)
		VALUES ($1,$2,'active','user','{}'::jsonb),($3,$4,'active','user','{}'::jsonb)
	`, legacyID, "legacy-before-insights", registeredID, "registered-before-insights"); err != nil {
		t.Fatalf("seed pre-insights users: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO self_registrations (
			id,user_id,status,expires_at,completed_at,created_at,updated_at
		) VALUES ($1,$2,'completed',$3,$4,$5,$4)
	`, uuid.New(), registeredID, now.Add(time.Hour), now, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed authoritative self-registration: %v", err)
	}
	if err := runner.Migrate(10); err != nil {
		t.Fatalf("migrate to administrator insights schema: %v", err)
	}
	assertMigrationVersion(t, schema, 10)

	for _, test := range []struct {
		id   uuid.UUID
		want string
	}{{legacyID, "legacy"}, {registeredID, "self_registration"}} {
		var sourceValue string
		if err := schema.pool.QueryRow(ctx, `SELECT creation_source FROM users WHERE id=$1`, test.id).Scan(&sourceValue); err != nil {
			t.Fatalf("load creation source for %s: %v", test.id, err)
		}
		if sourceValue != test.want {
			t.Fatalf("creation source for %s = %q, want %q", test.id, sourceValue, test.want)
		}
	}
	var columnDefault *string
	if err := schema.pool.QueryRow(ctx, `
		SELECT column_default FROM information_schema.columns
		WHERE table_schema=$1 AND table_name='users' AND column_name='creation_source'
	`, schema.name).Scan(&columnDefault); err != nil {
		t.Fatalf("inspect creation_source default: %v", err)
	}
	if columnDefault != nil {
		t.Fatalf("creation_source default = %q, want NULL", *columnDefault)
	}
	if _, err := schema.pool.Exec(ctx, `INSERT INTO users (id,username) VALUES ($1,$2)`, uuid.New(), "missing-source"); !isPostgresCode(err, "23502") {
		t.Fatalf("missing creation_source error = %v, want not-null violation", err)
	}
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,creation_source) VALUES ($1,$2,'guessed')
	`, uuid.New(), "invalid-source"); !isPostgresCode(err, "23514") {
		t.Fatalf("invalid creation_source error = %v, want check violation", err)
	}
}

func TestAdminUserCreationSourcesInsightsAndExactActivity(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run administrator insights migrations: %v", err)
	}
	ctx := context.Background()
	store := user.NewStoreForRP(schema.pool, "auth.example.test")
	service := user.NewService(store)

	bootstrap, err := service.BootstrapInitialAdmin(ctx, "bootstrap-admin", "bootstrap-password-123", "")
	if err != nil || !bootstrap.Created {
		t.Fatalf("bootstrap administrator result=%#v err=%v", bootstrap, err)
	}
	bootstrapUser, err := service.GetByUsername(ctx, "bootstrap-admin")
	if err != nil {
		t.Fatalf("load bootstrap administrator: %v", err)
	}
	assertUserCreationSource(t, schema, bootstrapUser.ID, "bootstrap", nil)

	legacyUser, err := service.Create(ctx, models.CreateUserRequest{
		Username: "legacy-internal", Password: "legacy-password-123",
	})
	if err != nil {
		t.Fatalf("create legacy internal user: %v", err)
	}
	assertUserCreationSource(t, schema, legacyUser.ID, "legacy", nil)

	mutation := audit.MutationAudit{
		Event: models.AuditUserCreated, ActorID: bootstrapUser.ID, ActorName: bootstrapUser.Username,
		Result: "success", RiskLevel: "low", IPAddress: "192.0.2.20", UserAgent: "insights-integration",
	}
	managed, err := service.CreateAdmin(ctx, models.CreateUserRequest{
		Username: "managed-account", Password: "managed-password-123", DisplayName: "Managed Account",
	}, mutation)
	if err != nil {
		t.Fatalf("create managed user: %v", err)
	}
	assertUserCreationSource(t, schema, managed.ID, "admin", &bootstrapUser.ID)
	var auditActor, auditTarget string
	if err := schema.pool.QueryRow(ctx, `
		SELECT payload->>'actor_id',payload->>'target_id'
		FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='user' AND aggregate_id=$2
	`, models.AuditUserCreated, managed.ID.String()).Scan(&auditActor, &auditTarget); err != nil {
		t.Fatalf("load managed-user audit: %v", err)
	}
	if auditActor != bootstrapUser.ID.String() || auditTarget != managed.ID.String() {
		t.Fatalf("managed-user audit actor=%q target=%q", auditActor, auditTarget)
	}

	providerUser := &models.User{
		ID: uuid.New(), Username: "provider-created", Status: models.UserStatusActive, Role: "user",
		AuthVersion: 1, SessionVersion: 1, Metadata: map[string]string{},
	}
	binding := &models.Identity{
		ID: uuid.New(), Provider: "github", ExternalID: "provider-external-user", Metadata: map[string]string{},
	}
	if err := identity.NewStore(schema.pool).CreateUserAndIdentity(ctx, providerUser, binding); err != nil {
		t.Fatalf("create provider user and identity: %v", err)
	}
	assertUserCreationSource(t, schema, providerUser.ID, "provider", nil)

	policy := configureRegistrationPolicy(t, schema, nil)
	registrationUser := registrationTestUser("self-created-insights", models.UserStatusActive)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := store.CreateRegistration(ctx, registrationUser, user.RegistrationCommitOptions{
		ExpiresAt: now.Add(72 * time.Hour), Now: now, Registration: policy,
		MailGate: runtimecoord.MailDeliveryGate{Mode: runtimecoord.MailModeFallback},
	}); err != nil {
		t.Fatalf("create self-registration source user: %v", err)
	}
	assertUserCreationSource(t, schema, registrationUser.ID, "self_registration", nil)

	overview, err := service.GetAdminOverview(ctx, managed.ID)
	if err != nil {
		t.Fatalf("load managed-user overview: %v", err)
	}
	if overview.User.ID != managed.ID || overview.CreationSource != "admin" || overview.SelfRegistration != nil ||
		overview.CreatedBy == nil || overview.CreatedBy.ID != bootstrapUser.ID {
		t.Fatalf("managed-user overview = %#v", overview)
	}
	registrationOverview, err := service.GetAdminOverview(ctx, registrationUser.ID)
	if err != nil {
		t.Fatalf("load self-registration overview: %v", err)
	}
	if registrationOverview.SelfRegistration == nil || registrationOverview.SelfRegistration.Status != "completed" ||
		registrationOverview.SelfRegistration.ExpiresAt.IsZero() {
		t.Fatalf("self-registration overview = %#v", registrationOverview)
	}

	confirmedAt := now.Add(-time.Hour)
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO user_totp_credentials (user_id,secret_ciphertext,confirmed_at)
		VALUES ($1,'encrypted-test-secret',$2)
	`, managed.ID, confirmedAt); err != nil {
		t.Fatalf("seed managed-user TOTP: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO user_recovery_codes (id,user_id,selector_hash,code_hash)
		VALUES ($1,$2,$3,'argon2-test-hash')
	`, uuid.New(), managed.ID, make([]byte, 32)); err != nil {
		t.Fatalf("seed managed-user recovery code: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO user_passkey_handles (rp_id,user_id,user_handle)
		VALUES ('auth.example.test',$1,$2)
	`, managed.ID, make([]byte, 32)); err != nil {
		t.Fatalf("seed managed-user Passkey handle: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO user_passkey_credentials (
			id,rp_id,user_id,credential_id,credential_ciphertext,name,clone_warning,last_used_at
		) VALUES ($1,'auth.example.test',$2,$3,'encrypted-passkey','Laptop',TRUE,$4)
	`, uuid.New(), managed.ID, []byte("credential-id"), confirmedAt); err != nil {
		t.Fatalf("seed managed-user Passkey credential: %v", err)
	}
	security, err := service.GetAdminSecurity(ctx, managed.ID)
	if err != nil {
		t.Fatalf("load managed-user security: %v", err)
	}
	if !security.HasPassword || !security.TOTPEnrolled || security.RecoveryCodesRemaining != 1 ||
		security.PasskeysEnrolled != 1 || security.PasskeyCloneWarnings != 1 || security.LastPasskeyUsedAt == nil {
		t.Fatalf("managed-user security = %#v", security)
	}

	actorName := managed.Username
	targetType := "user"
	targetID := managed.ID.String()
	unrelatedTarget := legacyUser.ID.String()
	auditStore := audit.NewStore(schema.pool)
	for _, entry := range []*models.AuditLog{
		{ID: uuid.New(), Event: models.AuditUserLogin, ActorID: &managed.ID, ActorName: &actorName, Result: "success", RiskLevel: "low", Details: map[string]interface{}{}, CreatedAt: now},
		{ID: uuid.New(), Event: models.AuditUserUpdated, ActorID: &bootstrapUser.ID, TargetType: &targetType, TargetID: &targetID, Result: "success", RiskLevel: "medium", Details: map[string]interface{}{}, CreatedAt: now.Add(-time.Second)},
		{ID: uuid.New(), Event: models.AuditUserUpdated, ActorID: &bootstrapUser.ID, TargetType: &targetType, TargetID: &unrelatedTarget, Result: "success", RiskLevel: "low", Details: map[string]interface{}{}, CreatedAt: now.Add(-2 * time.Second)},
	} {
		if err := auditStore.Record(ctx, entry); err != nil {
			t.Fatalf("record exact-activity fixture: %v", err)
		}
	}
	activity, err := auditStore.List(ctx, 1, 20, audit.ListFilter{SubjectUserID: &managed.ID})
	if err != nil {
		t.Fatalf("list exact user activity: %v", err)
	}
	if activity.Total != 2 || len(activity.Items) != 2 {
		t.Fatalf("exact user activity = %#v", activity)
	}
	exactTarget, err := auditStore.List(ctx, 1, 20, audit.ListFilter{TargetType: "user", TargetID: managed.ID.String()})
	if err != nil {
		t.Fatalf("list exact audit target: %v", err)
	}
	if exactTarget.Total != 1 || len(exactTarget.Items) != 1 || exactTarget.Items[0].TargetID == nil || *exactTarget.Items[0].TargetID != managed.ID.String() {
		t.Fatalf("exact audit target = %#v", exactTarget)
	}

	if _, err := schema.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, bootstrapUser.ID); err != nil {
		t.Fatalf("delete managed-user creator: %v", err)
	}
	overview, err = service.GetAdminOverview(ctx, managed.ID)
	if err != nil {
		t.Fatalf("reload managed-user overview after creator deletion: %v", err)
	}
	if overview.CreationSource != "admin" || overview.CreatedBy != nil {
		t.Fatalf("overview after creator deletion = %#v", overview)
	}
}

func assertUserCreationSource(t *testing.T, schema *postgresTestSchema, id uuid.UUID, wantSource string, wantCreator *uuid.UUID) {
	t.Helper()
	var source string
	var creator *uuid.UUID
	if err := schema.pool.QueryRow(context.Background(), `
		SELECT creation_source,created_by FROM users WHERE id=$1
	`, id).Scan(&source, &creator); err != nil {
		t.Fatalf("load creation provenance for %s: %v", id, err)
	}
	if source != wantSource || !equalOptionalUUID(creator, wantCreator) {
		t.Fatalf("creation provenance for %s = {%q %v}, want {%q %v}", id, source, creator, wantSource, wantCreator)
	}
}

func equalOptionalUUID(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
