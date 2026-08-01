package database_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/authorization"
	"github.com/nyasharp/nyauth/internal/avatar"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/settings"
	migrationfiles "github.com/nyasharp/nyauth/migrations"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestOAuthApplicationIdentityUpgradesSchema13WithoutInventingUsage(t *testing.T) {
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
	defer func() {
		if sourceErr, databaseErr := runner.Close(); sourceErr != nil || databaseErr != nil {
			t.Errorf("close migration runner: source=%v database=%v", sourceErr, databaseErr)
		}
	}()
	if err := runner.Migrate(13); err != nil {
		t.Fatalf("migrate isolated schema to version 13: %v", err)
	}

	ctx := context.Background()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,creation_source)
		VALUES ($1,'schema-13-user','active','user','legacy')
	`, userID); err != nil {
		t.Fatalf("insert schema-13 user: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO oauth_clients (
			id,name,redirect_uris,post_logout_redirect_uris,grants,scopes,optional_scopes,
			allowed_claims,is_public,access_policy,publisher_type,publisher_verification_status
		) VALUES ('schema-13-client','Schema 13 App',ARRAY['https://app.example/callback'],ARRAY[]::text[],
			ARRAY['authorization_code'],ARRAY['openid'],ARRAY[]::text[],ARRAY['sub'],TRUE,'open','system_managed','not_applicable')
	`); err != nil {
		t.Fatalf("insert schema-13 client: %v", err)
	}
	legacyTimestamp := time.Now().UTC().Add(-time.Hour)
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO oauth_authorizations (id,user_id,client_id,scopes,allowed_claims,granted_at,last_used_at)
		VALUES ($1,$2,'schema-13-client',ARRAY['openid'],ARRAY['sub'],$3,$3)
	`, uuid.New(), userID, legacyTimestamp); err != nil {
		t.Fatalf("insert schema-13 authorization: %v", err)
	}
	if err := runner.Up(); err != nil {
		t.Fatalf("upgrade isolated schema from 13 to 14: %v", err)
	}
	if err := database.ValidateSchemaVersion(ctx, schema.pool); err != nil {
		t.Fatalf("validate upgraded schema: %v", err)
	}

	var nameSnapshot string
	var identityRevision, authorizationRevision int64
	var lastUsedAt *time.Time
	if err := schema.pool.QueryRow(ctx, `
		SELECT client_name_snapshot,client_identity_revision,client_authorization_revision,last_used_at
		FROM oauth_authorizations WHERE user_id=$1 AND client_id='schema-13-client'
	`, userID).Scan(&nameSnapshot, &identityRevision, &authorizationRevision, &lastUsedAt); err != nil {
		t.Fatalf("read upgraded authorization: %v", err)
	}
	if nameSnapshot != "Schema 13 App" || identityRevision != 1 || authorizationRevision != 1 || lastUsedAt != nil {
		t.Fatalf("upgraded authorization snapshot=%q revisions=%d/%d last_used_at=%v", nameSnapshot, identityRevision, authorizationRevision, lastUsedAt)
	}
}

func TestOAuthApplicationIdentitySnapshotsAndReauthorization(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx := context.Background()
	ownerID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,creation_source)
		VALUES ($1,'application-owner','active','user','admin')
	`, ownerID); err != nil {
		t.Fatalf("insert owner: %v", err)
	}
	clientStore := client.NewStore(schema.pool)
	registered := &models.OAuthClient{
		ID: "application-identity-client", Name: "Original App", HomepageURI: "https://app.example",
		PrivacyPolicyURI: "https://app.example/privacy", TermsOfServiceURI: "https://app.example/terms",
		RedirectURIs: []string{"https://app.example/callback"}, PostLogoutRedirectURIs: []string{},
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"openid", "profile"},
		OptionalScopes: []string{}, AllowedClaims: []string{"sub", "name"}, IsPublic: true,
		AccessPolicy: models.ClientAccessOpen, OwnerID: ptrString(ownerID.String()), Metadata: map[string]string{},
		PublisherType: models.PublisherTypeUserRegistered, PublisherVerification: models.PublisherVerificationUnverified,
	}
	if err := clientStore.Create(ctx, registered); err != nil {
		t.Fatalf("create client: %v", err)
	}
	authorizations := authorization.NewStore(schema.pool)
	grantedAt := time.Now().UTC().Add(-time.Minute)
	if err := authorizations.Upsert(ctx, ownerID, registered.ID, []string{"openid"}, []string{"sub"}, grantedAt); err != nil {
		t.Fatalf("create authorization: %v", err)
	}
	items, err := authorizations.ListByUser(ctx, ownerID)
	if err != nil || len(items) != 1 || items[0].LastUsedAt != nil {
		t.Fatalf("unused authorization = %#v err=%v", items, err)
	}
	usedAt := grantedAt.Add(30 * time.Second).Truncate(time.Microsecond)
	if err := authorizations.MarkUsed(ctx, ownerID, registered.ID, usedAt); err != nil {
		t.Fatalf("mark authorization used: %v", err)
	}
	items, err = authorizations.ListByUser(ctx, ownerID)
	if err != nil || len(items) != 1 || items[0].LastUsedAt == nil || !items[0].LastUsedAt.Equal(usedAt) {
		t.Fatalf("used authorization = %#v err=%v", items, err)
	}
	mutation := audit.MutationAudit{
		Event: models.AuditClientUpdated, ActorID: ownerID, ActorName: "application-owner",
		Result: "success", RiskLevel: "medium",
	}
	expandedScopes := []string{"openid", "profile", "email"}
	expandedClaims := []string{"sub", "name", "email"}
	expanded, err := clientStore.UpdateRequestWithOAuthPolicy(ctx, registered.ID, models.UpdateClientRequest{
		Scopes: expandedScopes, AllowedClaims: expandedClaims,
	}, mutation, settings.Versioned[settings.OAuthPolicy]{Value: settings.DefaultOAuthPolicy()})
	if err != nil {
		t.Fatalf("expand application permissions: %v", err)
	}
	if expanded.AuthorizationRevision != 1 {
		t.Fatalf("scope expansion authorization revision = %d, want 1", expanded.AuthorizationRevision)
	}
	name := "Renamed App"
	homepage := "https://new.example"
	updated, err := clientStore.UpdateRequestWithOAuthPolicy(ctx, registered.ID, models.UpdateClientRequest{
		Name: &name, HomepageURI: &homepage,
	}, mutation, settings.Versioned[settings.OAuthPolicy]{Value: settings.DefaultOAuthPolicy()})
	if err != nil {
		t.Fatalf("update application identity: %v", err)
	}
	if updated.IdentityRevision != 2 || updated.AuthorizationRevision != 1 {
		t.Fatalf("identity update revisions = %d/%d, want 2/1", updated.IdentityRevision, updated.AuthorizationRevision)
	}
	items, err = authorizations.ListByUser(ctx, ownerID)
	if err != nil || len(items) != 1 {
		t.Fatalf("list authorization after identity update: items=%d err=%v", len(items), err)
	}
	if !items[0].ApplicationChanged || items[0].ReauthorizationRequired || items[0].ClientNameAtGrant != "Original App" || items[0].ClientName != name {
		t.Fatalf("identity change authorization = %#v", items[0])
	}

	redirects := []string{"https://new.example/callback"}
	updated, err = clientStore.UpdateRequestWithOAuthPolicy(ctx, registered.ID, models.UpdateClientRequest{
		RedirectURIs: redirects,
	}, mutation, settings.Versioned[settings.OAuthPolicy]{Value: settings.DefaultOAuthPolicy()})
	if err != nil {
		t.Fatalf("update high-risk application settings: %v", err)
	}
	if updated.AuthorizationRevision != 2 {
		t.Fatalf("authorization revision = %d, want 2", updated.AuthorizationRevision)
	}
	if err := authorizations.UpsertExpected(ctx, ownerID, registered.ID, []string{"openid"}, []string{"sub"}, time.Now().UTC(), 2, 1); err != authorization.ErrClientChanged {
		t.Fatalf("stale consent upsert error = %v, want ErrClientChanged", err)
	}
	items, err = authorizations.ListByUser(ctx, ownerID)
	if err != nil || len(items) != 1 || !items[0].ReauthorizationRequired {
		t.Fatalf("stale authorization after high-risk update: %#v err=%v", items, err)
	}

	if err := authorizations.Upsert(ctx, ownerID, registered.ID, []string{"openid"}, []string{"sub"}, time.Now().UTC()); err != nil {
		t.Fatalf("renew authorization: %v", err)
	}
	items, err = authorizations.ListByUser(ctx, ownerID)
	if err != nil || len(items) != 1 || items[0].ApplicationChanged || items[0].ReauthorizationRequired || items[0].ClientNameAtGrant != name || items[0].LastUsedAt != nil {
		t.Fatalf("renewed authorization = %#v err=%v", items, err)
	}
}

func TestClientLogoUsesSharedMediaLifecycle(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx := context.Background()
	clientStore := client.NewStore(schema.pool)
	registered := &models.OAuthClient{
		ID: "client-logo-lifecycle", Name: "Logo App", RedirectURIs: []string{"https://app.example/callback"},
		PostLogoutRedirectURIs: []string{}, Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"openid"},
		OptionalScopes: []string{}, AllowedClaims: []string{"sub"}, IsPublic: true, AccessPolicy: models.ClientAccessOpen,
		Metadata: map[string]string{}, PublisherType: models.PublisherTypeSystemManaged,
		PublisherVerification: models.PublisherVerificationNotApplicable,
	}
	if err := clientStore.Create(ctx, registered); err != nil {
		t.Fatalf("create client: %v", err)
	}
	localStore, err := avatar.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	media, err := avatar.NewService(avatar.NewRepository(schema.pool), localStore, avatar.NewProcessor())
	if err != nil {
		t.Fatal(err)
	}
	first, err := media.UploadClientLogo(ctx, registered.ID, bytes.NewReader(squarePNG(t, 128)), time.Now().UTC())
	if err != nil {
		t.Fatalf("upload client logo: %v", err)
	}
	loaded, err := clientStore.GetByID(ctx, registered.ID)
	if err != nil || loaded.CurrentLogoID == nil || *loaded.CurrentLogoID != first.String() || loaded.LogoURL == "" || loaded.IdentityRevision != 2 {
		t.Fatalf("client after logo upload = %#v err=%v", loaded, err)
	}
	object, err := media.OpenActiveClientLogoVariant(ctx, first, 128)
	if err != nil {
		t.Fatalf("open client logo: %v", err)
	}
	_ = object.Body.Close()
	second, err := media.UploadClientLogo(ctx, registered.ID, bytes.NewReader(squarePNG(t, 64)), time.Now().UTC().Add(time.Second))
	if err != nil || second == first {
		t.Fatalf("replace client logo id=%s err=%v", second, err)
	}
	var firstStatus string
	if err := schema.pool.QueryRow(ctx, `SELECT status FROM user_avatars WHERE id=$1`, first).Scan(&firstStatus); err != nil || firstStatus != "replaced" {
		t.Fatalf("first logo status=%q err=%v", firstStatus, err)
	}
	if _, err := media.DeleteClientLogo(ctx, registered.ID, time.Now().UTC().Add(2*time.Second)); err != nil {
		t.Fatalf("delete client logo: %v", err)
	}
	loaded, err = clientStore.GetByID(ctx, registered.ID)
	if err != nil || loaded.CurrentLogoID != nil || loaded.LogoURL != "" || loaded.IdentityRevision != 4 {
		t.Fatalf("client after logo deletion = %#v err=%v", loaded, err)
	}
	orphanedLogo, err := media.UploadClientLogo(ctx, registered.ID, bytes.NewReader(squarePNG(t, 96)), time.Now().UTC().Add(3*time.Second))
	if err != nil {
		t.Fatalf("upload logo before client deletion: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `DELETE FROM oauth_clients WHERE id=$1`, registered.ID); err != nil {
		t.Fatalf("delete client with active logo: %v", err)
	}
	var orphanOwner *string
	if err := schema.pool.QueryRow(ctx, `SELECT client_id FROM user_avatars WHERE id=$1`, orphanedLogo).Scan(&orphanOwner); err != nil || orphanOwner != nil {
		t.Fatalf("orphaned client logo owner=%v err=%v", orphanOwner, err)
	}
	pending, err := avatar.NewRepository(schema.pool).CountCleanupPending(ctx, avatar.StorageLocal)
	if err != nil || pending < 1 {
		t.Fatalf("orphaned client logo cleanup backlog=%d err=%v", pending, err)
	}
}

func ptrString(value string) *string { return &value }
