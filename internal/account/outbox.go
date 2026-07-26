package account

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
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	accountstats "github.com/nyasharp/nyauth/internal/stats"
)

const (
	defaultEmailArtifactExpiryBatchSize = 500
	maxEmailArtifactExpiryBatchSize     = 5000
)

// ExpireEmailArtifacts removes sensitive payloads as soon as their persisted
// deadline passes. It runs independently of sender availability so disabling
// SMTP or opening the circuit cannot retain expired plaintext envelopes. The
// per-table limit bounds lock and write amplification while allowing tokens and
// queued messages to make progress independently.
func (s *Store) ExpireEmailArtifacts(ctx context.Context, now time.Time, perTableLimit int) (int64, error) {
	if perTableLimit < 1 || perTableLimit > maxEmailArtifactExpiryBatchSize {
		return 0, fmt.Errorf("invalid email artifact expiry batch size")
	}
	now = now.UTC()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("starting email artifact expiry: %w", err)
	}
	defer tx.Rollback(ctx)
	tokenResult, err := tx.Exec(ctx, `
		WITH candidates AS (
			SELECT id FROM account_action_tokens
			WHERE consumed_at IS NULL AND revoked_at IS NULL AND expires_at<=$1
			ORDER BY expires_at,id
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		UPDATE account_action_tokens AS token
		SET revoked_at=$1,revoked_reason='expired',payload_ciphertext=''
		FROM candidates
		WHERE token.id=candidates.id
	`, now, perTableLimit)
	if err != nil {
		return 0, fmt.Errorf("expiring account action tokens: %w", err)
	}
	outboxRows, err := tx.Query(ctx, `
		WITH candidates AS (
			SELECT id FROM email_outbox
			WHERE status IN ('pending','failed','sending') AND expires_at<=$1
			ORDER BY expires_at,id
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		UPDATE email_outbox AS outbox
		SET status='expired',encrypted_message='',last_error=NULL,
		    locked_at=NULL,locked_by=NULL,updated_at=$1
		FROM candidates
		WHERE outbox.id=candidates.id
		RETURNING outbox.expires_at
	`, now, perTableLimit)
	if err != nil {
		return 0, fmt.Errorf("expiring email outbox messages: %w", err)
	}
	type expiryBucket struct {
		expiresAt time.Time
		count     int64
	}
	expiredByDay := make(map[string]expiryBucket)
	var expiredOutbox int64
	for outboxRows.Next() {
		var expiresAt time.Time
		if err := outboxRows.Scan(&expiresAt); err != nil {
			outboxRows.Close()
			return 0, fmt.Errorf("reading expired email outbox messages: %w", err)
		}
		day := expiresAt.UTC().Format("2006-01-02")
		bucket := expiredByDay[day]
		bucket.expiresAt = expiresAt
		bucket.count++
		expiredByDay[day] = bucket
		expiredOutbox++
	}
	if err := outboxRows.Err(); err != nil {
		outboxRows.Close()
		return 0, fmt.Errorf("reading expired email outbox messages: %w", err)
	}
	outboxRows.Close()
	for _, bucket := range expiredByDay {
		if err := accountstats.AddMailDailyTx(ctx, tx, bucket.expiresAt, accountstats.MailDailyDelta{Expired: bucket.count}); err != nil {
			return 0, fmt.Errorf("recording expired email statistics: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("committing email artifact expiry: %w", err)
	}
	return tokenResult.RowsAffected() + expiredOutbox, nil
}

func (s *Store) ClaimEmailBatch(
	ctx context.Context,
	workerID string,
	limit int,
	now time.Time,
	lease time.Duration,
	gate *runtimecoord.MailDeliveryGate,
) ([]OutboxEmail, error) {
	workerID = strings.TrimSpace(workerID)
	if workerID == "" || len(workerID) > 128 {
		return nil, fmt.Errorf("valid email worker ID is required")
	}
	if limit < 1 || limit > 100 || lease <= 0 {
		return nil, fmt.Errorf("invalid email outbox claim parameters")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if gate != nil {
		if err := runtimecoord.RequireMailDeliveryGate(ctx, tx, *gate); err != nil {
			return nil, err
		}
	}
	rows, err := tx.Query(ctx, `
		WITH candidates AS (
			SELECT id FROM email_outbox
			WHERE expires_at>$1 AND (
				(status IN ('pending','failed') AND available_at<=$1)
				OR (status='sending' AND locked_at<$2)
			)
			ORDER BY available_at,created_at
			FOR UPDATE SKIP LOCKED
			LIMIT $3
		)
		UPDATE email_outbox AS outbox
		SET status='sending',attempt_count=attempt_count+1,locked_at=$1,locked_by=$4,updated_at=$1
		FROM candidates WHERE outbox.id=candidates.id
		RETURNING outbox.id,outbox.user_id,outbox.message_type,outbox.recipient_hash,
		          outbox.encrypted_message,outbox.status,outbox.attempt_count,outbox.available_at,
		          outbox.locked_at,outbox.locked_by,outbox.expires_at,outbox.created_at
	`, now, now.Add(-lease), limit, workerID)
	if err != nil {
		return nil, fmt.Errorf("claiming email outbox messages: %w", err)
	}
	defer rows.Close()
	claimed := make([]OutboxEmail, 0, limit)
	for rows.Next() {
		var item OutboxEmail
		var userID uuid.UUID
		if err := rows.Scan(
			&item.ID, &userID, &item.MessageType, &item.RecipientHash, &item.EncryptedMessage,
			&item.Status, &item.AttemptCount, &item.AvailableAt, &item.LockedAt, &item.LockedBy,
			&item.ExpiresAt, &item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning claimed email: %w", err)
		}
		item.UserID = &userID
		claimed = append(claimed, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating claimed emails: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return claimed, nil
}

func (s *Store) MarkEmailSent(ctx context.Context, id uuid.UUID, workerID string, now time.Time) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting sent email update: %w", err)
	}
	defer tx.Rollback(ctx)
	var updatedID uuid.UUID
	err = tx.QueryRow(ctx, `
		UPDATE email_outbox SET status='sent',sent_at=$3,encrypted_message='',last_error=NULL,
		       locked_at=NULL,locked_by=NULL,updated_at=$3
		WHERE id=$1 AND status='sending' AND locked_by=$2
		RETURNING id
	`, id, workerID, now.UTC()).Scan(&updatedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrOutboxLeaseLost
	}
	if err != nil {
		return fmt.Errorf("marking email sent: %w", err)
	}
	if err := accountstats.AddMailDailyTx(ctx, tx, now, accountstats.MailDailyDelta{Sent: 1}); err != nil {
		return fmt.Errorf("recording sent email statistics: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing sent email update: %w", err)
	}
	return nil
}

func (s *Store) MarkEmailFailed(ctx context.Context, id uuid.UUID, workerID, failure string, retryAt, now time.Time) error {
	if len(failure) > 512 {
		failure = truncateUTF8(failure, 512)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting failed email update: %w", err)
	}
	defer tx.Rollback(ctx)
	var status string
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `
		UPDATE email_outbox SET
			status=CASE WHEN expires_at<=$4 THEN 'expired' ELSE 'failed' END,
			encrypted_message=CASE WHEN expires_at<=$4 THEN '' ELSE encrypted_message END,
			last_error=$3,available_at=CASE WHEN expires_at<=$4 THEN available_at ELSE $5 END,
			locked_at=NULL,locked_by=NULL,updated_at=$4
		WHERE id=$1 AND status='sending' AND locked_by=$2
		RETURNING status,expires_at
	`, id, workerID, failure, now.UTC(), retryAt.UTC()).Scan(&status, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrOutboxLeaseLost
	}
	if err != nil {
		return fmt.Errorf("marking email failed: %w", err)
	}
	if err := accountstats.AddMailDailyTx(ctx, tx, now, accountstats.MailDailyDelta{FailedAttempts: 1}); err != nil {
		return fmt.Errorf("recording failed email statistics: %w", err)
	}
	if err := accountstats.AddMailFailureMinuteTx(ctx, tx, now, 1); err != nil {
		return fmt.Errorf("recording rolling email failure statistics: %w", err)
	}
	if status == "expired" {
		if err := accountstats.AddMailDailyTx(ctx, tx, expiresAt, accountstats.MailDailyDelta{Expired: 1}); err != nil {
			return fmt.Errorf("recording expired failed email statistics: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing failed email update: %w", err)
	}
	return nil
}

func (s *Store) MarkEmailRejected(ctx context.Context, id uuid.UUID, workerID string, now time.Time) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting rejected email update: %w", err)
	}
	defer tx.Rollback(ctx)
	var updatedID uuid.UUID
	err = tx.QueryRow(ctx, `
		UPDATE email_outbox SET status='rejected',encrypted_message='',last_error='permanent SMTP recipient failure',
		       locked_at=NULL,locked_by=NULL,updated_at=$3
		WHERE id=$1 AND status='sending' AND locked_by=$2
		RETURNING id
	`, id, workerID, now.UTC()).Scan(&updatedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrOutboxLeaseLost
	}
	if err != nil {
		return fmt.Errorf("marking email rejected: %w", err)
	}
	if err := accountstats.AddMailDailyTx(ctx, tx, now, accountstats.MailDailyDelta{
		FailedAttempts: 1,
		Rejected:       1,
	}); err != nil {
		return fmt.Errorf("recording rejected email statistics: %w", err)
	}
	if err := accountstats.AddMailFailureMinuteTx(ctx, tx, now, 1); err != nil {
		return fmt.Errorf("recording rolling rejected email statistics: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing rejected email update: %w", err)
	}
	return nil
}

func (s *Store) EmailOutboxBacklog(ctx context.Context, now time.Time) (int64, time.Duration, error) {
	var backlog int64
	var oldestCreatedAt *time.Time
	err := s.db.QueryRow(ctx, `
		SELECT COUNT(*),MIN(created_at) FROM email_outbox
		WHERE status IN ('pending','failed','sending') AND expires_at>$1
	`, now.UTC()).Scan(&backlog, &oldestCreatedAt)
	if err != nil {
		return 0, 0, fmt.Errorf("counting email outbox backlog: %w", err)
	}
	var oldestAge time.Duration
	if oldestCreatedAt != nil && now.After(*oldestCreatedAt) {
		oldestAge = now.Sub(*oldestCreatedAt)
	}
	return backlog, oldestAge, nil
}

type EmailSender interface {
	Send(ctx context.Context, message EmailMessage) error
}

type EmailSenderProvider interface {
	CurrentSender() (EmailSender, runtimecoord.MailDeliveryGate, bool)
}

type staticEmailSenderProvider struct{ sender EmailSender }

func (p staticEmailSenderProvider) CurrentSender() (EmailSender, runtimecoord.MailDeliveryGate, bool) {
	return p.sender, runtimecoord.MailDeliveryGate{}, p.sender != nil
}

type emailSenderRefresher interface {
	RefreshEmailSender(context.Context) error
}

type emailOutboxStore interface {
	ExpireEmailArtifacts(ctx context.Context, now time.Time, perTableLimit int) (int64, error)
	ClaimEmailBatch(ctx context.Context, workerID string, limit int, now time.Time, lease time.Duration, gate *runtimecoord.MailDeliveryGate) ([]OutboxEmail, error)
	MarkEmailSent(ctx context.Context, id uuid.UUID, workerID string, now time.Time) error
	MarkEmailFailed(ctx context.Context, id uuid.UUID, workerID, failure string, retryAt, now time.Time) error
	MarkEmailRejected(ctx context.Context, id uuid.UUID, workerID string, now time.Time) error
}

type emailBacklogStore interface {
	EmailOutboxBacklog(ctx context.Context, now time.Time) (int64, time.Duration, error)
}

type DispatcherOptions struct {
	WorkerID                string
	MasterKeys              map[string][]byte
	BatchSize               int
	ArtifactExpiryBatchSize int
	Lease                   time.Duration
	Interval                time.Duration
	Clock                   func() time.Time
	OnError                 func(error)
	OnDelivery              func(context.Context, string, bool)
	OnSMTPError             func(context.Context, SMTPErrorCategory)
	OnBacklog               func(context.Context, int64, time.Duration)
}

type Dispatcher struct {
	store       emailOutboxStore
	senders     EmailSenderProvider
	workerID    string
	masterKeys  map[string][]byte
	batchSize   int
	expiryBatch int
	lease       time.Duration
	interval    time.Duration
	clock       func() time.Time
	onError     func(error)
	onDelivery  func(context.Context, string, bool)
	onSMTPError func(context.Context, SMTPErrorCategory)
	onBacklog   func(context.Context, int64, time.Duration)
}

func NewDispatcher(store *Store, sender EmailSender, options DispatcherOptions) (*Dispatcher, error) {
	return newDispatcher(store, sender, options)
}

func newDispatcher(store emailOutboxStore, sender EmailSender, options DispatcherOptions) (*Dispatcher, error) {
	return newDispatcherWithProvider(store, staticEmailSenderProvider{sender: sender}, options)
}

func NewDynamicDispatcher(store *Store, senders EmailSenderProvider, options DispatcherOptions) (*Dispatcher, error) {
	return newDispatcherWithProvider(store, senders, options)
}

func newDispatcherWithProvider(store emailOutboxStore, senders EmailSenderProvider, options DispatcherOptions) (*Dispatcher, error) {
	if store == nil || senders == nil {
		return nil, fmt.Errorf("email outbox store and sender provider are required")
	}
	if static, ok := senders.(staticEmailSenderProvider); ok && static.sender == nil {
		return nil, fmt.Errorf("email outbox store and sender are required")
	}
	options.WorkerID = strings.TrimSpace(options.WorkerID)
	if options.WorkerID == "" || len(options.WorkerID) > 128 {
		return nil, fmt.Errorf("valid email worker ID is required")
	}
	keys := make(map[string][]byte, len(options.MasterKeys))
	for keyID, key := range options.MasterKeys {
		if len(key) != 32 {
			return nil, fmt.Errorf("master key %q must contain exactly 32 bytes", keyID)
		}
		keys[keyID] = append([]byte(nil), key...)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one email envelope key is required")
	}
	if options.BatchSize == 0 {
		options.BatchSize = 20
	}
	if options.ArtifactExpiryBatchSize == 0 {
		options.ArtifactExpiryBatchSize = defaultEmailArtifactExpiryBatchSize
	}
	if options.Lease == 0 {
		options.Lease = 2 * time.Minute
	}
	if options.Interval == 0 {
		options.Interval = 5 * time.Second
	}
	if options.BatchSize < 1 || options.BatchSize > 100 ||
		options.ArtifactExpiryBatchSize < 1 || options.ArtifactExpiryBatchSize > maxEmailArtifactExpiryBatchSize ||
		options.Lease <= 0 || options.Interval <= 0 {
		return nil, fmt.Errorf("invalid email dispatcher settings")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	return &Dispatcher{
		store: store, senders: senders, workerID: options.WorkerID, masterKeys: keys,
		batchSize: options.BatchSize, expiryBatch: options.ArtifactExpiryBatchSize,
		lease: options.Lease, interval: options.Interval, clock: options.Clock,
		onError: options.OnError, onDelivery: options.OnDelivery, onSMTPError: options.OnSMTPError, onBacklog: options.OnBacklog,
	}, nil
}

func (d *Dispatcher) DispatchOnce(ctx context.Context) (int, error) {
	defer d.observeBacklog(ctx)
	now := d.clock().UTC()
	if _, err := d.store.ExpireEmailArtifacts(ctx, now, d.expiryBatch); err != nil {
		return 0, err
	}
	sender, gate, available := d.senders.CurrentSender()
	if !available {
		return 0, nil
	}
	var expectedGate *runtimecoord.MailDeliveryGate
	if gate.Mode != "" {
		expectedGate = &gate
	}
	items, err := d.store.ClaimEmailBatch(ctx, d.workerID, d.batchSize, now, d.lease, expectedGate)
	if err != nil {
		if errors.Is(err, runtimecoord.ErrMailDeliveryGateChanged) || errors.Is(err, runtimecoord.ErrMailCircuitOpen) {
			if refresher, ok := d.senders.(emailSenderRefresher); ok {
				if refreshErr := refresher.RefreshEmailSender(ctx); refreshErr != nil {
					return 0, fmt.Errorf("refreshing email sender after delivery state changed: %w", refreshErr)
				}
			}
			return 0, nil
		}
		return 0, err
	}
	processed := 0
	var dispatchErrors []error
	for i := range items {
		item := &items[i]
		message, err := decryptOutboxEnvelope(d.masterKeys, *item)
		if err != nil {
			dispatchErrors = append(dispatchErrors, d.fail(ctx, item, err, now))
			continue
		}
		if err := sender.Send(ctx, message); err != nil {
			dispatchErrors = append(dispatchErrors, d.fail(ctx, item, fmt.Errorf("sending email: %w", err), now))
			continue
		}
		if err := d.store.MarkEmailSent(ctx, item.ID, d.workerID, d.clock().UTC()); err != nil {
			d.recordDelivery(ctx, "failure", true)
			dispatchErrors = append(dispatchErrors, err)
			continue
		}
		d.recordDelivery(ctx, "success", false)
		processed++
	}
	return processed, errors.Join(dispatchErrors...)
}

// VerifyOutboxEnvelope authenticates and validates a persisted email without
// returning its sensitive plaintext. Recovery tooling uses this read-only
// check against restored database rows.
func VerifyOutboxEnvelope(masterKeys map[string][]byte, item OutboxEmail) error {
	_, err := decryptOutboxEnvelope(masterKeys, item)
	return err
}

func decryptOutboxEnvelope(masterKeys map[string][]byte, item OutboxEmail) (EmailMessage, error) {
	if item.UserID == nil {
		return EmailMessage{}, fmt.Errorf("email outbox item has no user binding")
	}
	plaintext, err := crypto.DecryptEnvelope(
		masterKeys, emailEnvelopePurpose, item.EncryptedMessage,
		emailAAD(item.ID, item.MessageType, *item.UserID),
	)
	if err != nil {
		return EmailMessage{}, fmt.Errorf("decrypting email envelope: %w", err)
	}
	var message EmailMessage
	if err := json.Unmarshal(plaintext, &message); err != nil {
		return EmailMessage{}, fmt.Errorf("decoding email envelope: %w", err)
	}
	if err := validateEmailMessage(message); err != nil {
		return EmailMessage{}, err
	}
	return message, nil
}

func (d *Dispatcher) Run(ctx context.Context) error {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		if _, err := d.DispatchOnce(ctx); err != nil && ctx.Err() == nil {
			if d.onError == nil {
				return err
			}
			d.onError(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (d *Dispatcher) fail(ctx context.Context, item *OutboxEmail, cause error, now time.Time) error {
	category, permanent := SMTPErrorDetails(cause)
	failure := sanitizeDispatchError(cause)
	safeCause := errors.New(failure)
	if category == SMTPErrorRecipient && permanent {
		markErr := d.store.MarkEmailRejected(
			ctx, item.ID, d.workerID, d.clock().UTC(),
		)
		d.recordDelivery(ctx, "failure", false)
		if d.onSMTPError != nil {
			d.onSMTPError(ctx, category)
		}
		if markErr != nil {
			return errors.Join(safeCause, markErr)
		}
		return safeCause
	}
	retryAt := now.Add(retryDelay(item.AttemptCount))
	markErr := d.store.MarkEmailFailed(ctx, item.ID, d.workerID, failure, retryAt, d.clock().UTC())
	retryScheduled := markErr == nil && item.ExpiresAt.After(now)
	d.recordDelivery(ctx, "failure", retryScheduled)
	if d.onSMTPError != nil {
		d.onSMTPError(ctx, category)
	}
	if markErr != nil {
		return errors.Join(safeCause, markErr)
	}
	return safeCause
}

func (d *Dispatcher) recordDelivery(ctx context.Context, result string, retryScheduled bool) {
	if d.onDelivery != nil {
		d.onDelivery(ctx, result, retryScheduled)
	}
}

func (d *Dispatcher) observeBacklog(ctx context.Context) {
	if d.onBacklog == nil || ctx.Err() != nil {
		return
	}
	store, ok := d.store.(emailBacklogStore)
	if !ok {
		return
	}
	backlog, oldestAge, err := store.EmailOutboxBacklog(ctx, d.clock().UTC())
	if err != nil {
		if d.onError != nil {
			d.onError(err)
		}
		return
	}
	d.onBacklog(ctx, backlog, oldestAge)
}

func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 7 {
		attempt = 7
	}
	return time.Duration(1<<(attempt-1)) * time.Minute
}

func sanitizeDispatchError(err error) string {
	if err == nil {
		return "unknown email delivery error"
	}
	var smtpErr *SMTPError
	if errors.As(err, &smtpErr) {
		switch smtpErr.Category {
		case SMTPErrorConfiguration:
			return "SMTP configuration failure"
		case SMTPErrorAuthentication:
			return "SMTP authentication failure"
		case SMTPErrorTLS:
			return "SMTP TLS failure"
		case SMTPErrorTransport:
			return "SMTP transport failure"
		case SMTPErrorRecipient:
			if smtpErr.Permanent {
				return "permanent SMTP recipient failure"
			}
			return "temporary SMTP recipient failure"
		default:
			return "SMTP delivery failure"
		}
	}
	message := strings.ReplaceAll(err.Error(), "\r", " ")
	message = strings.ReplaceAll(message, "\n", " ")
	if len(message) > 512 {
		message = truncateUTF8(message, 512)
	}
	return message
}

func validateEmailMessage(message EmailMessage) error {
	if _, err := normalizeEmail(message.To); err != nil {
		return fmt.Errorf("email outbox recipient is invalid: %w", err)
	}
	if strings.TrimSpace(message.Subject) == "" || containsHeaderBreak(message.Subject) {
		return fmt.Errorf("email outbox subject is invalid")
	}
	if message.TextBody == "" && message.HTMLBody == "" {
		return fmt.Errorf("email outbox body is empty")
	}
	return nil
}

func containsHeaderBreak(value string) bool {
	return strings.ContainsAny(value, "\r\n")
}

func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
