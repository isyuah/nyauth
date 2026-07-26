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
	"github.com/nyasharp/nyauth/internal/crypto"
)

func (s *Store) ClaimEmailBatch(ctx context.Context, workerID string, limit int, now time.Time, lease time.Duration) ([]OutboxEmail, error) {
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
	if _, err := tx.Exec(ctx, `
		UPDATE account_action_tokens SET revoked_at=$1,revoked_reason='expired',payload_ciphertext=''
		WHERE consumed_at IS NULL AND revoked_at IS NULL AND expires_at<=$1
	`, now); err != nil {
		return nil, fmt.Errorf("expiring account action tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE email_outbox SET status='expired',encrypted_message='',locked_at=NULL,locked_by=NULL,updated_at=$1
		WHERE status IN ('pending','failed','sending') AND expires_at<=$1
	`, now); err != nil {
		return nil, fmt.Errorf("expiring email outbox messages: %w", err)
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
	result, err := s.db.Exec(ctx, `
		UPDATE email_outbox SET status='sent',sent_at=$3,encrypted_message='',last_error=NULL,
		       locked_at=NULL,locked_by=NULL,updated_at=$3
		WHERE id=$1 AND status='sending' AND locked_by=$2
	`, id, workerID, now)
	if err != nil {
		return fmt.Errorf("marking email sent: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrOutboxLeaseLost
	}
	return nil
}

func (s *Store) MarkEmailFailed(ctx context.Context, id uuid.UUID, workerID, failure string, retryAt, now time.Time) error {
	if len(failure) > 512 {
		failure = truncateUTF8(failure, 512)
	}
	result, err := s.db.Exec(ctx, `
		UPDATE email_outbox SET
			status=CASE WHEN expires_at<=$4 THEN 'expired' ELSE 'failed' END,
			encrypted_message=CASE WHEN expires_at<=$4 THEN '' ELSE encrypted_message END,
			last_error=$3,available_at=CASE WHEN expires_at<=$4 THEN available_at ELSE $5 END,
			locked_at=NULL,locked_by=NULL,updated_at=$4
		WHERE id=$1 AND status='sending' AND locked_by=$2
	`, id, workerID, failure, now, retryAt)
	if err != nil {
		return fmt.Errorf("marking email failed: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrOutboxLeaseLost
	}
	return nil
}

func (s *Store) EmailOutboxBacklog(ctx context.Context, now time.Time) (int64, error) {
	var backlog int64
	err := s.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM email_outbox
		WHERE status IN ('pending','failed','sending') AND expires_at>$1
	`, now).Scan(&backlog)
	if err != nil {
		return 0, fmt.Errorf("counting email outbox backlog: %w", err)
	}
	return backlog, nil
}

type EmailSender interface {
	Send(ctx context.Context, message EmailMessage) error
}

type emailOutboxStore interface {
	ClaimEmailBatch(ctx context.Context, workerID string, limit int, now time.Time, lease time.Duration) ([]OutboxEmail, error)
	MarkEmailSent(ctx context.Context, id uuid.UUID, workerID string, now time.Time) error
	MarkEmailFailed(ctx context.Context, id uuid.UUID, workerID, failure string, retryAt, now time.Time) error
}

type emailBacklogStore interface {
	EmailOutboxBacklog(ctx context.Context, now time.Time) (int64, error)
}

type DispatcherOptions struct {
	WorkerID   string
	MasterKeys map[string][]byte
	BatchSize  int
	Lease      time.Duration
	Interval   time.Duration
	Clock      func() time.Time
	OnError    func(error)
	OnDelivery func(context.Context, string, bool)
	OnBacklog  func(context.Context, int64)
}

type Dispatcher struct {
	store      emailOutboxStore
	sender     EmailSender
	workerID   string
	masterKeys map[string][]byte
	batchSize  int
	lease      time.Duration
	interval   time.Duration
	clock      func() time.Time
	onError    func(error)
	onDelivery func(context.Context, string, bool)
	onBacklog  func(context.Context, int64)
}

func NewDispatcher(store *Store, sender EmailSender, options DispatcherOptions) (*Dispatcher, error) {
	return newDispatcher(store, sender, options)
}

func newDispatcher(store emailOutboxStore, sender EmailSender, options DispatcherOptions) (*Dispatcher, error) {
	if store == nil || sender == nil {
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
	if options.Lease == 0 {
		options.Lease = 2 * time.Minute
	}
	if options.Interval == 0 {
		options.Interval = 5 * time.Second
	}
	if options.BatchSize < 1 || options.BatchSize > 100 || options.Lease <= 0 || options.Interval <= 0 {
		return nil, fmt.Errorf("invalid email dispatcher settings")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	return &Dispatcher{
		store: store, sender: sender, workerID: options.WorkerID, masterKeys: keys,
		batchSize: options.BatchSize, lease: options.Lease, interval: options.Interval, clock: options.Clock,
		onError: options.OnError, onDelivery: options.OnDelivery, onBacklog: options.OnBacklog,
	}, nil
}

func (d *Dispatcher) DispatchOnce(ctx context.Context) (int, error) {
	defer d.observeBacklog(ctx)
	now := d.clock().UTC()
	items, err := d.store.ClaimEmailBatch(ctx, d.workerID, d.batchSize, now, d.lease)
	if err != nil {
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
		if err := d.sender.Send(ctx, message); err != nil {
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
	retryAt := now.Add(retryDelay(item.AttemptCount))
	markErr := d.store.MarkEmailFailed(ctx, item.ID, d.workerID, sanitizeDispatchError(cause), retryAt, d.clock().UTC())
	retryScheduled := markErr == nil && item.ExpiresAt.After(now)
	d.recordDelivery(ctx, "failure", retryScheduled)
	if markErr != nil {
		return errors.Join(cause, markErr)
	}
	return cause
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
	backlog, err := store.EmailOutboxBacklog(ctx, d.clock().UTC())
	if err != nil {
		if d.onError != nil {
			d.onError(err)
		}
		return
	}
	d.onBacklog(ctx, backlog)
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
