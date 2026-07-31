package server

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/internal/telemetry"
)

const operationalAlertInterval = 30 * time.Second

type operationalAlert struct {
	Code      string  `json:"code"`
	Current   float64 `json:"current"`
	Threshold float64 `json:"threshold"`
	Unit      string  `json:"unit"`
}

type operationalAlertSnapshot struct {
	Status    string             `json:"status"`
	CheckedAt *time.Time         `json:"checked_at,omitempty"`
	Active    []operationalAlert `json:"active"`
}

type operationalSignals struct {
	mailBacklog          int64
	mailOldestSeconds    float64
	auditBacklog         int64
	auditOldestSeconds   float64
	avatarCleanupPending int64
}

type operationalAlertMonitor struct {
	db        *pgxpool.Pool
	settings  *settings.Manager
	telemetry *telemetry.Runtime
	snapshot  atomic.Pointer[operationalAlertSnapshot]
}

func newOperationalAlertMonitor(db *pgxpool.Pool, manager *settings.Manager, runtime *telemetry.Runtime) *operationalAlertMonitor {
	monitor := &operationalAlertMonitor{db: db, settings: manager, telemetry: runtime}
	monitor.snapshot.Store(&operationalAlertSnapshot{Status: "pending", Active: []operationalAlert{}})
	return monitor
}

func (m *operationalAlertMonitor) Snapshot() operationalAlertSnapshot {
	if m == nil {
		return operationalAlertSnapshot{Status: "unavailable", Active: []operationalAlert{}}
	}
	if snapshot := m.snapshot.Load(); snapshot != nil {
		copyValue := *snapshot
		copyValue.Active = append(make([]operationalAlert, 0, len(snapshot.Active)), snapshot.Active...)
		return copyValue
	}
	return operationalAlertSnapshot{Status: "pending", Active: []operationalAlert{}}
}

func (m *operationalAlertMonitor) Run(ctx context.Context) {
	if m == nil || m.db == nil || m.settings == nil {
		return
	}
	m.refresh(ctx)
	ticker := time.NewTicker(operationalAlertInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.refresh(ctx)
		}
	}
}

func (m *operationalAlertMonitor) refresh(ctx context.Context) {
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	signals, err := readOperationalSignals(checkCtx, m.db)
	if err != nil {
		previous := m.Snapshot()
		previous.Status = "unavailable"
		m.snapshot.Store(&previous)
		if ctx.Err() == nil {
			slog.WarnContext(ctx, "operational alert sampling failed", "error", err)
		}
		return
	}
	policy := m.settings.Observability()
	active, states := evaluateOperationalAlerts(policy, signals)
	for code, exceeded := range states {
		m.telemetry.RecordOperationalAlert(ctx, code, exceeded)
	}
	now := time.Now().UTC()
	m.snapshot.Store(&operationalAlertSnapshot{Status: "ok", CheckedAt: &now, Active: active})
}

func evaluateOperationalAlerts(policy settings.Observability, signals operationalSignals) ([]operationalAlert, map[string]bool) {
	checks := []struct {
		code               string
		current, threshold float64
		unit               string
	}{
		{"mail_backlog", float64(signals.mailBacklog), float64(policy.Alerts.MailBacklogCount), "count"},
		{"mail_oldest_pending", signals.mailOldestSeconds, policy.MailOldestPendingDuration().Seconds(), "seconds"},
		{"audit_outbox_backlog", float64(signals.auditBacklog), float64(policy.Alerts.AuditOutboxBacklogCount), "count"},
		{"audit_oldest_pending", signals.auditOldestSeconds, policy.AuditOldestPendingDuration().Seconds(), "seconds"},
		{"avatar_cleanup_pending", float64(signals.avatarCleanupPending), float64(policy.Alerts.AvatarCleanupPendingCount), "count"},
	}
	active := make([]operationalAlert, 0, len(checks))
	states := make(map[string]bool, len(checks))
	for _, check := range checks {
		exceeded := check.current >= check.threshold
		states[check.code] = exceeded
		if exceeded {
			active = append(active, operationalAlert{Code: check.code, Current: check.current, Threshold: check.threshold, Unit: check.unit})
		}
	}
	return active, states
}

func readOperationalSignals(ctx context.Context, db *pgxpool.Pool) (operationalSignals, error) {
	var result operationalSignals
	err := db.QueryRow(ctx, `
		SELECT
		  (SELECT COUNT(*) FROM email_outbox WHERE status IN ('pending','failed','sending') AND expires_at > NOW()),
		  COALESCE((SELECT EXTRACT(EPOCH FROM (NOW()-MIN(created_at))) FROM email_outbox WHERE status IN ('pending','failed','sending') AND expires_at > NOW()),0),
		  (SELECT COUNT(*) FROM audit_event_outbox WHERE status IN ('pending','failed','processing')),
		  COALESCE((SELECT EXTRACT(EPOCH FROM (NOW()-MIN(created_at))) FROM audit_event_outbox WHERE status IN ('pending','failed','processing')),0),
		  (SELECT COUNT(*) FROM user_avatars WHERE storage_deleted_at IS NULL AND (status IN ('staging','replaced','failed','deleted') OR user_id IS NULL))
	`).Scan(&result.mailBacklog, &result.mailOldestSeconds, &result.auditBacklog, &result.auditOldestSeconds, &result.avatarCleanupPending)
	return result, err
}
