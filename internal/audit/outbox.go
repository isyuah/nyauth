package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nyasharp/nyauth/pkg/models"
)

var ErrOutboxLeaseLost = errors.New("audit outbox lease is no longer owned by this worker")

// OutboxEvent is the durable representation of an audit event waiting to be
// copied into audit_logs. The outbox ID is also used as the audit log ID so a
// retry after an uncertain commit is idempotent.
type OutboxEvent struct {
	ID            uuid.UUID
	Event         string
	AggregateType string
	AggregateID   string
	Payload       map[string]any
	Status        string
	AttemptCount  int
	AvailableAt   time.Time
	LockedAt      *time.Time
	LockedBy      *string
	CreatedAt     time.Time
}

type outboxExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// Enqueue persists an event outside an existing transaction. State-changing
// code should prefer EnqueueTx so the state change and its audit event commit
// atomically.
func (s *Store) Enqueue(ctx context.Context, event OutboxEvent) error {
	return enqueue(ctx, s.db, event)
}

// EnqueueTx persists an event in the caller's transaction.
func EnqueueTx(ctx context.Context, tx pgx.Tx, event OutboxEvent) error {
	if tx == nil {
		return fmt.Errorf("audit outbox transaction is required")
	}
	return enqueue(ctx, tx, event)
}

func enqueue(ctx context.Context, execer outboxExecer, event OutboxEvent) error {
	now := time.Now().UTC()
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	event.Event = strings.TrimSpace(event.Event)
	event.AggregateType = strings.TrimSpace(event.AggregateType)
	event.AggregateID = strings.TrimSpace(event.AggregateID)
	if event.Event == "" || len(event.Event) > 64 {
		return fmt.Errorf("audit event name must contain 1 to 64 characters")
	}
	if event.AggregateType == "" || len(event.AggregateType) > 32 {
		return fmt.Errorf("audit aggregate type must contain 1 to 32 characters")
	}
	if event.AggregateID == "" || len(event.AggregateID) > 128 {
		return fmt.Errorf("audit aggregate ID must contain 1 to 128 characters")
	}
	if event.Payload == nil {
		event.Payload = map[string]any{}
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = now
	} else {
		event.CreatedAt = event.CreatedAt.UTC()
	}
	if event.AvailableAt.IsZero() {
		event.AvailableAt = event.CreatedAt
	} else {
		event.AvailableAt = event.AvailableAt.UTC()
	}
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		return fmt.Errorf("encoding audit outbox payload: %w", err)
	}
	_, err = execer.Exec(ctx, `
		INSERT INTO audit_event_outbox (
			id,event,aggregate_type,aggregate_id,payload,status,attempt_count,
			available_at,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,'pending',0,$6,$7,$7)
	`, event.ID, event.Event, event.AggregateType, event.AggregateID, payload, event.AvailableAt, event.CreatedAt)
	if err != nil {
		return fmt.Errorf("enqueuing audit event: %w", err)
	}
	return nil
}

func (s *Store) ClaimAuditBatch(ctx context.Context, workerID string, limit int, now time.Time, lease time.Duration) ([]OutboxEvent, error) {
	workerID = strings.TrimSpace(workerID)
	if workerID == "" || len(workerID) > 128 {
		return nil, fmt.Errorf("valid audit worker ID is required")
	}
	if limit < 1 || limit > 100 || lease <= 0 {
		return nil, fmt.Errorf("invalid audit outbox claim parameters")
	}
	now = now.UTC()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting audit outbox claim: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		WITH candidates AS (
			SELECT id FROM audit_event_outbox
			WHERE (status IN ('pending','failed') AND available_at<=$1)
			   OR (status='processing' AND locked_at<$2)
			ORDER BY available_at,created_at
			FOR UPDATE SKIP LOCKED
			LIMIT $3
		)
		UPDATE audit_event_outbox AS outbox
		SET status='processing',attempt_count=attempt_count+1,locked_at=$1,locked_by=$4,updated_at=$1
		FROM candidates WHERE outbox.id=candidates.id
		RETURNING outbox.id,outbox.event,outbox.aggregate_type,outbox.aggregate_id,outbox.payload,
		          outbox.status,outbox.attempt_count,outbox.available_at,outbox.locked_at,
		          outbox.locked_by,outbox.created_at
	`, now, now.Add(-lease), limit, workerID)
	if err != nil {
		return nil, fmt.Errorf("claiming audit outbox events: %w", err)
	}
	defer rows.Close()

	claimed := make([]OutboxEvent, 0, limit)
	for rows.Next() {
		var item OutboxEvent
		var payload []byte
		if err := rows.Scan(
			&item.ID, &item.Event, &item.AggregateType, &item.AggregateID, &payload,
			&item.Status, &item.AttemptCount, &item.AvailableAt, &item.LockedAt,
			&item.LockedBy, &item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning claimed audit event: %w", err)
		}
		if err := json.Unmarshal(payload, &item.Payload); err != nil {
			return nil, fmt.Errorf("decoding claimed audit event %s: %w", item.ID, err)
		}
		claimed = append(claimed, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating claimed audit events: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing audit outbox claim: %w", err)
	}
	return claimed, nil
}

// DeliverAuditEvent writes the final audit row and marks the outbox row as
// processed in one transaction. The lease update happens first, preventing a
// stale worker from writing after another instance has reclaimed the event.
func (s *Store) DeliverAuditEvent(ctx context.Context, event OutboxEvent, entry *models.AuditLog, workerID string, now time.Time) error {
	if entry == nil || entry.ID != event.ID {
		return fmt.Errorf("audit log must use the outbox event ID")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting audit delivery: %w", err)
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `
		UPDATE audit_event_outbox SET status='processed',processed_at=$3,last_error=NULL,
		       locked_at=NULL,locked_by=NULL,updated_at=$3
		WHERE id=$1 AND status='processing' AND locked_by=$2
	`, event.ID, workerID, now.UTC())
	if err != nil {
		return fmt.Errorf("marking audit event processed: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrOutboxLeaseLost
	}
	if entry.Details == nil {
		entry.Details = map[string]any{}
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = event.CreatedAt.UTC()
	}
	insertTag, err := tx.Exec(ctx, `
		INSERT INTO audit_logs (
			id,event,actor_id,actor_name,target_type,target_id,ip_address,user_agent,
			result,risk_level,details,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (id,created_at) DO NOTHING
	`, entry.ID, entry.Event, entry.ActorID, entry.ActorName, entry.TargetType, entry.TargetID,
		entry.IPAddress, entry.UserAgent, entry.Result, entry.RiskLevel, entry.Details, entry.CreatedAt)
	if err != nil {
		return fmt.Errorf("inserting delivered audit log: %w", err)
	}
	if insertTag.RowsAffected() == 1 {
		if err := updateLoginAggregateTx(ctx, tx, entry, now.UTC()); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing audit delivery: %w", err)
	}
	return nil
}

func updateLoginAggregateTx(ctx context.Context, tx pgx.Tx, entry *models.AuditLog, refreshedAt time.Time) error {
	var successful, failed int64
	switch {
	case entry.Event == models.AuditUserLogin && entry.Result == "success":
		successful = 1
	case entry.Event == models.AuditUserLoginFailed && entry.Result == "failure":
		failed = 1
	default:
		return nil
	}
	day := entry.CreatedAt.UTC().Format("2006-01-02")
	if _, err := tx.Exec(ctx, `
		INSERT INTO login_stats_daily (day, successful_logins, failed_logins, refreshed_at)
		VALUES ($1::date, $2, $3, $4)
		ON CONFLICT (day) DO UPDATE SET
			successful_logins = login_stats_daily.successful_logins + EXCLUDED.successful_logins,
			failed_logins = login_stats_daily.failed_logins + EXCLUDED.failed_logins,
			refreshed_at = EXCLUDED.refreshed_at
	`, day, successful, failed, refreshedAt); err != nil {
		return fmt.Errorf("updating login statistics aggregate: %w", err)
	}
	return nil
}

func (s *Store) MarkAuditEventFailed(ctx context.Context, id uuid.UUID, workerID, failure string, retryAt, now time.Time) error {
	failure = sanitizeOutboxError(failure)
	result, err := s.db.Exec(ctx, `
		UPDATE audit_event_outbox SET status='failed',last_error=$3,available_at=$4,
		       locked_at=NULL,locked_by=NULL,updated_at=$5
		WHERE id=$1 AND status='processing' AND locked_by=$2
	`, id, workerID, failure, retryAt.UTC(), now.UTC())
	if err != nil {
		return fmt.Errorf("marking audit event failed: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrOutboxLeaseLost
	}
	return nil
}

// CleanupProcessedOutbox removes a bounded batch of already-delivered events.
// The durable audit_logs row remains subject to the longer audit retention
// policy; failed and pending events are never removed here.
func (s *Store) CleanupProcessedOutbox(ctx context.Context, before time.Time, limit int) (int64, error) {
	if before.IsZero() || limit < 1 || limit > 50_000 {
		return 0, fmt.Errorf("invalid audit outbox cleanup parameters")
	}
	tag, err := s.db.Exec(ctx, `
		WITH expired AS (
			SELECT id FROM audit_event_outbox
			WHERE status='processed' AND processed_at < $1
			ORDER BY processed_at
			LIMIT $2
		)
		DELETE FROM audit_event_outbox outbox
		USING expired
		WHERE outbox.id=expired.id
	`, before.UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("cleaning processed audit outbox: %w", err)
	}
	return tag.RowsAffected(), nil
}

type auditOutboxStore interface {
	ClaimAuditBatch(context.Context, string, int, time.Time, time.Duration) ([]OutboxEvent, error)
	DeliverAuditEvent(context.Context, OutboxEvent, *models.AuditLog, string, time.Time) error
	MarkAuditEventFailed(context.Context, uuid.UUID, string, string, time.Time, time.Time) error
}

type DispatcherOptions struct {
	WorkerID  string
	BatchSize int
	Lease     time.Duration
	Interval  time.Duration
	Clock     func() time.Time
	OnError   func(context.Context, string, error)
}

type Dispatcher struct {
	store     auditOutboxStore
	workerID  string
	batchSize int
	lease     time.Duration
	interval  time.Duration
	clock     func() time.Time
	onError   func(context.Context, string, error)
}

func NewDispatcher(store *Store, options DispatcherOptions) (*Dispatcher, error) {
	return newDispatcher(store, options)
}

func newDispatcher(store auditOutboxStore, options DispatcherOptions) (*Dispatcher, error) {
	if store == nil {
		return nil, fmt.Errorf("audit outbox store is required")
	}
	options.WorkerID = strings.TrimSpace(options.WorkerID)
	if options.WorkerID == "" || len(options.WorkerID) > 128 {
		return nil, fmt.Errorf("valid audit worker ID is required")
	}
	if options.BatchSize == 0 {
		options.BatchSize = 50
	}
	if options.Lease == 0 {
		options.Lease = 2 * time.Minute
	}
	if options.Interval == 0 {
		options.Interval = 2 * time.Second
	}
	if options.BatchSize < 1 || options.BatchSize > 100 || options.Lease <= 0 || options.Interval <= 0 {
		return nil, fmt.Errorf("invalid audit dispatcher settings")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	return &Dispatcher{
		store: store, workerID: options.WorkerID, batchSize: options.BatchSize,
		lease: options.Lease, interval: options.Interval, clock: options.Clock, onError: options.OnError,
	}, nil
}

func (d *Dispatcher) DispatchOnce(ctx context.Context) (int, error) {
	now := d.clock().UTC()
	items, err := d.store.ClaimAuditBatch(ctx, d.workerID, d.batchSize, now, d.lease)
	if err != nil {
		d.report(ctx, "audit.outbox.claim", err)
		return 0, err
	}
	processed := 0
	var dispatchErrors []error
	for _, item := range items {
		entry, err := auditLogFromOutbox(item)
		if err == nil {
			err = d.store.DeliverAuditEvent(ctx, item, entry, d.workerID, d.clock().UTC())
		}
		if err == nil {
			processed++
			continue
		}
		retryAt := now.Add(auditRetryDelay(item.AttemptCount))
		markErr := d.store.MarkAuditEventFailed(ctx, item.ID, d.workerID, err.Error(), retryAt, d.clock().UTC())
		combined := errors.Join(err, markErr)
		d.report(ctx, item.Event, combined)
		dispatchErrors = append(dispatchErrors, combined)
	}
	return processed, errors.Join(dispatchErrors...)
}

func (d *Dispatcher) Run(ctx context.Context) error {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		if _, err := d.DispatchOnce(ctx); err != nil && ctx.Err() == nil && d.onError == nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (d *Dispatcher) report(ctx context.Context, event string, err error) {
	if d.onError != nil && err != nil && ctx.Err() == nil {
		d.onError(ctx, event, err)
	}
}

func auditLogFromOutbox(event OutboxEvent) (*models.AuditLog, error) {
	if event.ID == uuid.Nil || strings.TrimSpace(event.Event) == "" {
		return nil, fmt.Errorf("audit outbox event identity is invalid")
	}
	payload := event.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	result, err := payloadString(payload, "result", "success")
	if err != nil || (result != "success" && result != "failure") {
		return nil, fmt.Errorf("audit event result is invalid")
	}
	risk, err := payloadString(payload, "risk_level", "low")
	if err != nil || !validRiskLevel(risk) {
		return nil, fmt.Errorf("audit event risk level is invalid")
	}
	actorID, err := payloadUUID(payload, "actor_id")
	if err != nil {
		return nil, err
	}
	actorName, err := payloadOptionalString(payload, "actor_name")
	if err != nil {
		return nil, err
	}
	targetType, err := payloadOptionalString(payload, "target_type")
	if err != nil {
		return nil, err
	}
	targetID, err := payloadOptionalString(payload, "target_id")
	if err != nil {
		return nil, err
	}
	if targetType == nil && strings.TrimSpace(event.AggregateType) != "" {
		value := event.AggregateType
		targetType = &value
	}
	if targetID == nil && strings.TrimSpace(event.AggregateID) != "" {
		value := event.AggregateID
		targetID = &value
	}
	ipAddress, err := payloadOptionalString(payload, "ip_address")
	if err != nil {
		return nil, err
	}
	userAgent, err := payloadOptionalString(payload, "user_agent")
	if err != nil {
		return nil, err
	}
	details := map[string]any{}
	if rawDetails, ok := payload["details"]; ok {
		mapped, ok := rawDetails.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("audit event details must be an object")
		}
		for key, value := range mapped {
			details[key] = value
		}
	}
	reserved := map[string]struct{}{
		"actor_id": {}, "actor_name": {}, "target_type": {}, "target_id": {},
		"ip_address": {}, "user_agent": {}, "result": {}, "risk_level": {}, "details": {},
	}
	for key, value := range payload {
		if _, ok := reserved[key]; !ok {
			details[key] = value
		}
	}
	createdAt := event.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	return &models.AuditLog{
		ID: event.ID, Event: event.Event, ActorID: actorID, ActorName: actorName,
		TargetType: targetType, TargetID: targetID, IPAddress: ipAddress, UserAgent: userAgent,
		Result: result, RiskLevel: risk, Details: details, CreatedAt: createdAt,
	}, nil
}

func payloadString(payload map[string]any, key, fallback string) (string, error) {
	value, ok := payload[key]
	if !ok || value == nil {
		return fallback, nil
	}
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("audit event %s must be a string", key)
	}
	return strings.TrimSpace(text), nil
}

func payloadOptionalString(payload map[string]any, key string) (*string, error) {
	value, ok := payload[key]
	if !ok || value == nil {
		return nil, nil
	}
	text, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("audit event %s must be a string", key)
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}
	return &text, nil
}

func payloadUUID(payload map[string]any, key string) (*uuid.UUID, error) {
	value, err := payloadOptionalString(payload, key)
	if err != nil || value == nil {
		return nil, err
	}
	parsed, err := uuid.Parse(*value)
	if err != nil {
		return nil, fmt.Errorf("audit event %s must be a UUID", key)
	}
	return &parsed, nil
}

func validRiskLevel(value string) bool {
	switch value {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func auditRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 7 {
		attempt = 7
	}
	return time.Duration(1<<(attempt-1)) * time.Minute
}

func sanitizeOutboxError(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	if strings.TrimSpace(value) == "" {
		value = "unknown audit delivery error"
	}
	if len(value) <= 512 {
		return value
	}
	value = value[:512]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
