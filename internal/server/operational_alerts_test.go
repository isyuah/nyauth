package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nyasharp/nyauth/internal/settings"
)

func TestOperationalAlertSnapshotPreservesEmptyArrayContract(t *testing.T) {
	monitor := newOperationalAlertMonitor(nil, nil, nil)
	snapshot := monitor.Snapshot()
	if snapshot.Active == nil {
		t.Fatal("snapshot active alerts must be an empty array, not nil")
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(payload), `{"status":"pending","active":[]}`; got != want {
		t.Fatalf("snapshot JSON = %s, want %s", got, want)
	}
}

func TestOperationalAlertsUseConfiguredThresholdsWithoutInventingCorrelations(t *testing.T) {
	policy := settings.DefaultObservability()
	policy.Alerts.MailBacklogCount = 10
	policy.Alerts.MailOldestPendingAge = "5m"
	policy.Alerts.AuditOutboxBacklogCount = 20
	policy.Alerts.AuditOldestPendingAge = "2m"
	policy.Alerts.AvatarCleanupPendingCount = 3
	active, states := evaluateOperationalAlerts(policy, operationalSignals{
		mailBacklog: 9, mailOldestSeconds: (5 * time.Minute).Seconds(),
		auditBacklog: 20, auditOldestSeconds: (2*time.Minute - time.Second).Seconds(),
		avatarCleanupPending: 3,
	})
	for _, code := range []string{"mail_oldest_pending", "audit_outbox_backlog", "avatar_cleanup_pending"} {
		if !states[code] {
			t.Fatalf("%s should be active: %#v", code, states)
		}
	}
	for _, code := range []string{"mail_backlog", "audit_oldest_pending"} {
		if states[code] {
			t.Fatalf("%s should be inactive: %#v", code, states)
		}
	}
	if len(active) != 3 {
		t.Fatalf("active alerts = %#v", active)
	}
}

func TestReadOperationalSignalsUsesOnlyPendingWork(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	now := time.Now().UTC()
	if _, err := testApp.pool.Exec(context.Background(), `
		INSERT INTO audit_event_outbox (event,aggregate_type,aggregate_id,payload,status,available_at,created_at,updated_at)
		VALUES ('test.pending','test','pending','{}'::jsonb,'pending',$1,$1,$1),
		       ('test.done','test','done','{}'::jsonb,'processed',$1,$1,$1)
	`, now.Add(-3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	signals, err := readOperationalSignals(t.Context(), testApp.pool)
	if err != nil {
		t.Fatal(err)
	}
	if signals.auditBacklog != 1 || signals.auditOldestSeconds < 179 || signals.mailBacklog != 0 || signals.avatarCleanupPending != 0 {
		t.Fatalf("signals = %#v", signals)
	}
}
