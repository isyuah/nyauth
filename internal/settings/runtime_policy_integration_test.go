package settings

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestRuntimePolicySettingsCASAuditRollbackAndRetention(t *testing.T) {
	schema := newSecuritySettingsTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run settings migrations: %v", err)
	}
	ctx := t.Context()
	managerA := NewManager(schema.pool, Branding{Title: "Policy A"})
	managerB := NewManager(schema.pool, Branding{Title: "Policy B"})
	mutation := func(actor string) audit.MutationAudit {
		return audit.MutationAudit{
			Event: models.AuditSettingsUpdated, ActorID: uuid.New(), ActorName: actor,
			Result: "success", RiskLevel: "critical", IPAddress: "192.0.2.90",
		}
	}

	initial := DefaultProtection()
	initial.OwnedClientDefaultLimit = 20
	if revision, err := managerA.SetProtection(ctx, initial, 0, "policy-a", "", mutation("policy-a")); err != nil || revision != 1 {
		t.Fatalf("initial protection setting revision=%d err=%v", revision, err)
	}
	if err := managerB.Load(ctx); err != nil {
		t.Fatalf("load second manager: %v", err)
	}

	left := initial
	left.OwnedClientDefaultLimit = 21
	right := initial
	right.OwnedClientDefaultLimit = 22
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, candidate := range []Protection{left, right} {
		candidate := candidate
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := managerB.SetProtection(ctx, candidate, 1, "policy-b", "", mutation("policy-b"))
			results <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	succeeded, conflicted := 0, 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrRevisionConflict):
			conflicted++
		default:
			t.Fatalf("concurrent protection update error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent protection results success=%d conflict=%d, want 1/1", succeeded, conflicted)
	}
	if err := managerA.Load(ctx); err != nil {
		t.Fatalf("reconcile first manager after missed notification: %v", err)
	}
	if snapshot := managerA.ProtectionSnapshot(); snapshot.Revision != 2 ||
		(snapshot.Value.OwnedClientDefaultLimit != 21 && snapshot.Value.OwnedClientDefaultLimit != 22) {
		t.Fatalf("reconciled protection snapshot = %#v", snapshot)
	}
	var protectionAudits int
	if err := schema.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='settings' AND aggregate_id='protection'
	`, models.AuditSettingsUpdated).Scan(&protectionAudits); err != nil {
		t.Fatalf("count protection audits: %v", err)
	}
	if protectionAudits != 2 {
		t.Fatalf("protection audit rows = %d, want 2", protectionAudits)
	}

	oauthPolicy := DefaultOAuthPolicy()
	oauthPolicy.SelfServiceClientCreationEnabled = false
	oauthPolicy.MaxRedirectURIs = 8
	oauthPolicy.AllowedScopes = append(oauthPolicy.AllowedScopes, "legacy.read")
	oauthPolicy.ScopeDefinitions["legacy.read"] = OAuthScopeDefinition{
		DisplayName: "Legacy read", Description: "Read an existing integration resource.",
		Claims: []string{"preferred_username"}, AssignmentPolicy: OAuthAssignmentAdminOnly, RiskLevel: OAuthRiskSensitive,
	}
	if revision, err := managerA.SetOAuthPolicy(ctx, oauthPolicy, 0, "policy-a", mutation("policy-a")); err != nil || revision != 1 {
		t.Fatalf("store OAuth policy revision=%d err=%v", revision, err)
	}
	if _, err := managerB.SetOAuthPolicy(ctx, DefaultOAuthPolicy(), 0, "policy-b", mutation("policy-b")); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale OAuth policy update error = %v", err)
	}
	if err := managerB.Load(ctx); err != nil {
		t.Fatalf("reload OAuth policy: %v", err)
	}
	if snapshot := managerB.OAuthPolicySnapshot(); snapshot.Revision != 1 || !SameOAuthPolicy(snapshot.Value, oauthPolicy) {
		t.Fatalf("loaded OAuth policy = %#v", snapshot)
	}
	retiredPolicy := oauthPolicy
	retiredPolicy.AllowedScopes = slices.DeleteFunc(slices.Clone(oauthPolicy.AllowedScopes), func(scope string) bool { return scope == "legacy.read" })
	retiredPolicy.ScopeDefinitions = maps.Clone(oauthPolicy.ScopeDefinitions)
	delete(retiredPolicy.ScopeDefinitions, "legacy.read")
	if revision, err := managerA.SetOAuthPolicy(ctx, retiredPolicy, 1, "policy-a", mutation("policy-a")); err != nil || revision != 2 {
		t.Fatalf("retire OAuth scope revision=%d err=%v", revision, err)
	}
	if err := managerB.Load(ctx); err != nil {
		t.Fatalf("reload retired OAuth policy: %v", err)
	}
	retiredSnapshot := managerB.OAuthPolicySnapshot()
	if retiredSnapshot.Revision != 2 || retiredSnapshot.Value.AllowsScope("legacy.read") {
		t.Fatalf("retired OAuth policy snapshot = %#v", retiredSnapshot)
	}
	if definition, ok := retiredSnapshot.Value.ScopeDefinition("legacy.read"); !ok || definition.DisplayName != "Legacy read" {
		t.Fatalf("retired OAuth scope definition = %#v, exists=%v", definition, ok)
	}
	var oauthAudits int
	if err := schema.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='settings' AND aggregate_id='oauth'
	`, models.AuditSettingsUpdated).Scan(&oauthAudits); err != nil {
		t.Fatalf("count OAuth policy audits: %v", err)
	}
	if oauthAudits != 2 {
		t.Fatalf("OAuth policy audit rows = %d, want 2", oauthAudits)
	}

	communications := DefaultCommunications()
	communications.SiteBanner = SiteBanner{
		Version: 1, Enabled: true, Severity: SiteBannerSeverityInfo,
		Title: "Planned maintenance", Message: "Read-only mode starts soon.", Dismissible: true,
	}
	if revision, stored, err := managerA.SetCommunications(ctx, communications, 0, "policy-a", mutation("policy-a")); err != nil || revision != 1 || stored.SiteBanner.Version != 1 {
		t.Fatalf("store communications revision=%d err=%v", revision, err)
	}
	if _, _, err := managerB.SetCommunications(ctx, DefaultCommunications(), 0, "policy-b", mutation("policy-b")); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale communications update error = %v", err)
	}
	staleWriter := NewManager(schema.pool, Branding{Title: "Stale writer"})
	emailOnly := communications
	emailOnly.Email.Footer = "Updated {{site_name}} footer"
	if revision, stored, err := staleWriter.SetCommunications(ctx, emailOnly, 1, "policy-stale", mutation("policy-stale")); err != nil || revision != 2 || stored.SiteBanner.Version != 1 {
		t.Fatalf("stale-instance email update revision=%d site_banner=%d err=%v", revision, stored.SiteBanner.Version, err)
	}
	if err := managerB.Load(ctx); err != nil {
		t.Fatalf("reload communications: %v", err)
	}
	if snapshot := managerB.CommunicationsSnapshot(); snapshot.Revision != 2 || snapshot.Value.SiteBanner.Title != "Planned maintenance" || snapshot.Value.SiteBanner.Version != 1 {
		t.Fatalf("loaded communications = %#v", snapshot)
	}
	republished := managerB.Communications()
	republished.SiteBanner.Message = "Read-only mode begins now."
	if revision, stored, err := managerB.SetCommunications(ctx, republished, 2, "policy-b", mutation("policy-b")); err != nil || revision != 3 || stored.SiteBanner.Version != 2 {
		t.Fatalf("republished communications revision=%d site_banner=%d err=%v", revision, stored.SiteBanner.Version, err)
	}
	var communicationAudits int
	if err := schema.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='settings' AND aggregate_id='communications'
	`, models.AuditSettingsUpdated).Scan(&communicationAudits); err != nil {
		t.Fatalf("count communication audits: %v", err)
	}
	if communicationAudits != 3 {
		t.Fatalf("communication audit rows = %d, want 3", communicationAudits)
	}

	observability := DefaultObservability()
	observability.LogLevel = LogLevelWarn
	observability.Alerts.MailBacklogCount = 25
	var appliedObservability Versioned[Observability]
	managerA.SetObservabilityApply(func(snapshot Versioned[Observability]) { appliedObservability = snapshot })
	if revision, err := managerA.SetObservability(ctx, observability, 0, "policy-a", mutation("policy-a")); err != nil || revision != 1 {
		t.Fatalf("store observability revision=%d err=%v", revision, err)
	}
	if appliedObservability.Revision != 1 || appliedObservability.Value.LogLevel != LogLevelWarn {
		t.Fatalf("applied observability = %#v", appliedObservability)
	}
	if _, err := managerB.SetObservability(ctx, DefaultObservability(), 0, "policy-b", mutation("policy-b")); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale observability update error = %v", err)
	}
	if err := managerB.Load(ctx); err != nil {
		t.Fatalf("reload observability: %v", err)
	}
	if snapshot := managerB.ObservabilitySnapshot(); snapshot.Revision != 1 || snapshot.Value.Alerts.MailBacklogCount != 25 {
		t.Fatalf("loaded observability = %#v", snapshot)
	}
	var observabilityAudits int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1 AND aggregate_type='settings' AND aggregate_id='observability'`, models.AuditSettingsUpdated).Scan(&observabilityAudits); err != nil || observabilityAudits != 1 {
		t.Fatalf("observability audit rows=%d err=%v", observabilityAudits, err)
	}

	lifecycle := DefaultLifecycle(365)
	lifecycle.AuditRetentionDays = 90
	if _, err := managerA.SetLifecycle(ctx, lifecycle, 0, "policy-a", "", mutation("policy-a")); !errors.Is(err, ErrRetentionConfirmation) {
		t.Fatalf("retention shortening without confirmation error = %v", err)
	}
	var lifecycleRows int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM runtime_settings WHERE key='lifecycle'`).Scan(&lifecycleRows); err != nil {
		t.Fatalf("count lifecycle rows: %v", err)
	}
	if lifecycleRows != 0 {
		t.Fatalf("unconfirmed retention change stored %d rows", lifecycleRows)
	}
	if revision, err := managerA.SetLifecycle(
		ctx, lifecycle, 0, "policy-a", RetentionConfirmation(90), mutation("policy-a"),
	); err != nil || revision != 1 {
		t.Fatalf("store lifecycle revision=%d err=%v", revision, err)
	}
	resolved, err := ResolveAuditRetention(ctx, schema.pool, 365*24*time.Hour)
	if err != nil || resolved != 90*24*time.Hour {
		t.Fatalf("resolved audit retention = %v err=%v", resolved, err)
	}

	badMutation := mutation("policy-a")
	badMutation.Details = map[string]any{"client_secret": "must-not-persist"}
	changed := lifecycle
	changed.SessionAbsoluteTTL = "48h"
	if _, err := managerA.SetLifecycle(ctx, changed, 1, "policy-a", "", badMutation); err == nil {
		t.Fatal("lifecycle setting succeeded after audit payload rejection")
	}
	var raw []byte
	var revision int64
	if err := schema.pool.QueryRow(ctx, `SELECT value,revision FROM runtime_settings WHERE key='lifecycle'`).Scan(&raw, &revision); err != nil {
		t.Fatalf("load lifecycle after audit rollback: %v", err)
	}
	var persisted Lifecycle
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("decode lifecycle after audit rollback: %v", err)
	}
	if revision != 1 || persisted != lifecycle {
		t.Fatalf("lifecycle after audit rollback revision=%d value=%#v", revision, persisted)
	}
}

func TestRuntimePolicySettingsSynchronizeByNotification(t *testing.T) {
	schema := newSecuritySettingsTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run settings migrations: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	writer := NewManager(schema.pool, Branding{Title: "Writer"})
	reader := NewManager(schema.pool, Branding{Title: "Reader"})
	if err := reader.Load(ctx); err != nil {
		t.Fatalf("initial reader load: %v", err)
	}
	reader.StartSynchronization(ctx)
	// The listener owns its connection asynchronously. Publishing a second
	// bounded notification removes scheduler timing from this integration test.
	time.Sleep(200 * time.Millisecond)
	policy := DefaultProtection()
	policy.Login.IdentityLimit = 9
	if _, err := writer.SetProtection(ctx, policy, 0, "writer", "", audit.MutationAudit{
		Event: models.AuditSettingsUpdated, ActorID: uuid.New(), ActorName: "writer",
		Result: "success", RiskLevel: "critical",
	}); err != nil {
		t.Fatalf("write protection setting: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `SELECT pg_notify('nyauth_settings_changed','protection')`); err != nil {
		t.Fatalf("publish synchronization probe: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if snapshot := reader.ProtectionSnapshot(); snapshot.Revision == 1 && snapshot.Value.Login.IdentityLimit == 9 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("reader did not load notified protection setting: %#v", reader.ProtectionSnapshot())
}
