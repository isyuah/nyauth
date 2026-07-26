package account

import (
	"context"
	"errors"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
)

type fakeOutboxStore struct {
	items       []OutboxEmail
	sent        []uuid.UUID
	failed      []uuid.UUID
	rejected    []uuid.UUID
	failureText string
	retryAt     time.Time
	backlog     int64
	oldestAge   time.Duration
	claims      int
	expirations int
	expiryLimit int
	claimErr    error
	claimGate   *runtimecoord.MailDeliveryGate
}

func (f *fakeOutboxStore) EmailOutboxBacklog(context.Context, time.Time) (int64, time.Duration, error) {
	return f.backlog, f.oldestAge, nil
}

func (f *fakeOutboxStore) ExpireEmailArtifacts(_ context.Context, _ time.Time, perTableLimit int) (int64, error) {
	f.expirations++
	f.expiryLimit = perTableLimit
	return 0, nil
}

func (f *fakeOutboxStore) ClaimEmailBatch(_ context.Context, _ string, _ int, _ time.Time, _ time.Duration, gate *runtimecoord.MailDeliveryGate) ([]OutboxEmail, error) {
	f.claims++
	f.claimGate = gate
	return f.items, f.claimErr
}

func (f *fakeOutboxStore) MarkEmailSent(_ context.Context, id uuid.UUID, _ string, _ time.Time) error {
	f.sent = append(f.sent, id)
	return nil
}

func (f *fakeOutboxStore) MarkEmailFailed(_ context.Context, id uuid.UUID, _ string, failure string, retryAt, _ time.Time) error {
	f.failed = append(f.failed, id)
	f.failureText = failure
	f.retryAt = retryAt
	return nil
}

func (f *fakeOutboxStore) MarkEmailRejected(_ context.Context, id uuid.UUID, _ string, _ time.Time) error {
	f.rejected = append(f.rejected, id)
	f.failureText = "permanent SMTP recipient failure"
	return nil
}

type fakeSender struct {
	messages []EmailMessage
	err      error
}

type sequenceSenderProvider struct {
	senders   []EmailSender
	gate      runtimecoord.MailDeliveryGate
	calls     int
	refreshes int
}

func (p *sequenceSenderProvider) CurrentSender() (EmailSender, runtimecoord.MailDeliveryGate, bool) {
	if p.calls >= len(p.senders) {
		return nil, p.gate, false
	}
	sender := p.senders[p.calls]
	p.calls++
	return sender, p.gate, sender != nil
}

func (p *sequenceSenderProvider) RefreshEmailSender(context.Context) error {
	p.refreshes++
	return nil
}

func (f *fakeSender) Send(_ context.Context, message EmailMessage) error {
	f.messages = append(f.messages, message)
	return f.err
}

func encryptedTestEmail(t *testing.T) OutboxEmail {
	t.Helper()
	service := newTestService(t, &fakeServiceStore{})
	userID := uuid.New()
	item, err := service.newOutboxEmail(userID, MessageEmailVerification, EmailMessage{
		To: "alice@example.test", Subject: "Verify", TextBody: "Verification body",
	}, testNow)
	if err != nil {
		t.Fatalf("newOutboxEmail: %v", err)
	}
	item.Status = "sending"
	item.AttemptCount = 1
	worker := "worker-1"
	item.LockedBy = &worker
	return *item
}

func TestDispatcherDecryptsAndMarksMessageSent(t *testing.T) {
	item := encryptedTestEmail(t)
	store := &fakeOutboxStore{items: []OutboxEmail{item}}
	sender := &fakeSender{}
	dispatcher, err := newDispatcher(store, sender, DispatcherOptions{
		WorkerID: "worker-1", MasterKeys: map[string][]byte{"primary": testKey}, Clock: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("newDispatcher: %v", err)
	}
	processed, err := dispatcher.DispatchOnce(context.Background())
	if err != nil {
		t.Fatalf("DispatchOnce: %v", err)
	}
	if processed != 1 || len(store.sent) != 1 || len(sender.messages) != 1 {
		t.Fatalf("processed=%d sent=%d messages=%d", processed, len(store.sent), len(sender.messages))
	}
	if sender.messages[0].To != "alice@example.test" {
		t.Fatalf("recipient = %q", sender.messages[0].To)
	}
}

func TestVerifyOutboxEnvelopeRejectsTampering(t *testing.T) {
	item := encryptedTestEmail(t)
	if err := VerifyOutboxEnvelope(map[string][]byte{"primary": testKey}, item); err != nil {
		t.Fatalf("VerifyOutboxEnvelope(valid) error = %v", err)
	}
	item.EncryptedMessage += "x"
	if err := VerifyOutboxEnvelope(map[string][]byte{"primary": testKey}, item); err == nil {
		t.Fatal("VerifyOutboxEnvelope accepted tampered ciphertext")
	}
}

func TestDispatcherPersistsFailureAndBackoff(t *testing.T) {
	item := encryptedTestEmail(t)
	item.AttemptCount = 3
	store := &fakeOutboxStore{items: []OutboxEmail{item}}
	sender := &fakeSender{err: errors.New("temporary SMTP failure")}
	dispatcher, err := newDispatcher(store, sender, DispatcherOptions{
		WorkerID: "worker-1", MasterKeys: map[string][]byte{"primary": testKey}, Clock: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("newDispatcher: %v", err)
	}
	processed, err := dispatcher.DispatchOnce(context.Background())
	if processed != 0 || err == nil || len(store.failed) != 1 {
		t.Fatalf("processed=%d err=%v failed=%d", processed, err, len(store.failed))
	}
	if store.retryAt != testNow.Add(4*time.Minute) || !strings.Contains(store.failureText, "temporary SMTP failure") {
		t.Fatalf("retryAt=%s failure=%q", store.retryAt, store.failureText)
	}
}

func TestDispatcherReportsDeliveryRetryAndBacklogMetrics(t *testing.T) {
	item := encryptedTestEmail(t)
	store := &fakeOutboxStore{items: []OutboxEmail{item}, backlog: 3}
	sender := &fakeSender{err: errors.New("temporary SMTP failure")}
	var result string
	var retryScheduled bool
	var backlog int64
	var oldestAge time.Duration
	expectedOldestAge := 12 * time.Minute
	store.oldestAge = expectedOldestAge
	dispatcher, err := newDispatcher(store, sender, DispatcherOptions{
		WorkerID: "worker-1", MasterKeys: map[string][]byte{"primary": testKey}, Clock: func() time.Time { return testNow },
		OnDelivery: func(_ context.Context, currentResult string, retry bool) {
			result, retryScheduled = currentResult, retry
		},
		OnBacklog: func(_ context.Context, currentBacklog int64, currentOldestAge time.Duration) {
			backlog, oldestAge = currentBacklog, currentOldestAge
		},
	})
	if err != nil {
		t.Fatalf("newDispatcher: %v", err)
	}
	_, _ = dispatcher.DispatchOnce(context.Background())
	if result != "failure" || !retryScheduled || backlog != 3 || oldestAge != expectedOldestAge {
		t.Fatalf("result=%q retry=%v backlog=%d oldest_age=%s", result, retryScheduled, backlog, oldestAge)
	}
}

func TestDynamicDispatcherPinsClaimedBatchToValidatedSenderSnapshot(t *testing.T) {
	firstItem := encryptedTestEmail(t)
	secondItem := encryptedTestEmail(t)
	store := &fakeOutboxStore{items: []OutboxEmail{firstItem, secondItem}}
	firstSender := &fakeSender{}
	secondSender := &fakeSender{}
	versionID := uuid.New()
	provider := &sequenceSenderProvider{
		senders: []EmailSender{firstSender, secondSender},
		gate:    runtimecoord.MailDeliveryGate{Mode: runtimecoord.MailModeActive, VersionID: &versionID},
	}
	dispatcher, err := newDispatcherWithProvider(store, provider, DispatcherOptions{
		WorkerID: "worker-1", MasterKeys: map[string][]byte{"primary": testKey}, Clock: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("newDispatcherWithProvider: %v", err)
	}
	processed, err := dispatcher.DispatchOnce(context.Background())
	if err != nil {
		t.Fatalf("DispatchOnce: %v", err)
	}
	if processed != 2 || provider.calls != 1 || len(firstSender.messages) != 2 || len(secondSender.messages) != 0 {
		t.Fatalf("processed=%d snapshots=%d first=%d second=%d", processed, provider.calls, len(firstSender.messages), len(secondSender.messages))
	}
	if store.claimGate == nil || store.claimGate.Mode != runtimecoord.MailModeActive || store.claimGate.VersionID == nil || *store.claimGate.VersionID != versionID {
		t.Fatalf("claim gate = %#v", store.claimGate)
	}
}

func TestDynamicDispatcherDoesNotClaimWhileUnavailable(t *testing.T) {
	store := &fakeOutboxStore{items: []OutboxEmail{encryptedTestEmail(t)}}
	provider := &sequenceSenderProvider{senders: []EmailSender{nil}}
	dispatcher, err := newDispatcherWithProvider(store, provider, DispatcherOptions{
		WorkerID: "worker-1", MasterKeys: map[string][]byte{"primary": testKey}, Clock: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("newDispatcherWithProvider: %v", err)
	}
	processed, err := dispatcher.DispatchOnce(context.Background())
	if err != nil || processed != 0 || store.claims != 0 || store.expirations != 1 || store.expiryLimit != defaultEmailArtifactExpiryBatchSize {
		t.Fatalf("processed=%d claims=%d expirations=%d expiry_limit=%d err=%v", processed, store.claims, store.expirations, store.expiryLimit, err)
	}
}

func TestDynamicDispatcherRefreshesAfterAuthoritativeCircuitOpen(t *testing.T) {
	item := encryptedTestEmail(t)
	store := &fakeOutboxStore{items: []OutboxEmail{item}, claimErr: runtimecoord.ErrMailCircuitOpen}
	provider := &sequenceSenderProvider{
		senders: []EmailSender{&fakeSender{}},
		gate:    runtimecoord.MailDeliveryGate{Mode: runtimecoord.MailModeFallback},
	}
	dispatcher, err := newDispatcherWithProvider(store, provider, DispatcherOptions{
		WorkerID: "worker-1", MasterKeys: map[string][]byte{"primary": testKey}, Clock: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("newDispatcherWithProvider: %v", err)
	}
	processed, err := dispatcher.DispatchOnce(context.Background())
	if err != nil || processed != 0 || store.claims != 1 || provider.refreshes != 1 {
		t.Fatalf("processed=%d claims=%d refreshes=%d err=%v", processed, store.claims, provider.refreshes, err)
	}
}

func TestDispatcherPermanentlyRejectsRecipientWithoutRetry(t *testing.T) {
	item := encryptedTestEmail(t)
	store := &fakeOutboxStore{items: []OutboxEmail{item}}
	const leakedRecipient = "rejected@example.test"
	sender := &fakeSender{err: &SMTPError{
		Category: SMTPErrorRecipient, Operation: "sending SMTP RCPT TO", Permanent: true,
		Err: &textproto.Error{Code: 550, Msg: "mailbox unavailable for " + leakedRecipient},
	}}
	dispatcher, err := newDispatcher(store, sender, DispatcherOptions{
		WorkerID: "worker-1", MasterKeys: map[string][]byte{"primary": testKey}, Clock: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("newDispatcher: %v", err)
	}
	processed, err := dispatcher.DispatchOnce(context.Background())
	if processed != 0 || err == nil || len(store.rejected) != 1 || len(store.failed) != 0 {
		t.Fatalf("processed=%d err=%v rejected=%d failed=%d", processed, err, len(store.rejected), len(store.failed))
	}
	if !store.retryAt.IsZero() || store.failureText != "permanent SMTP recipient failure" {
		t.Fatalf("retryAt=%s failure=%q", store.retryAt, store.failureText)
	}
	if strings.Contains(err.Error(), leakedRecipient) || strings.Contains(err.Error(), "550") || strings.Contains(err.Error(), "mailbox unavailable") {
		t.Fatalf("dispatcher returned raw SMTP response: %q", err)
	}
}

func TestDispatcherRedactsRetryableSMTPFailure(t *testing.T) {
	item := encryptedTestEmail(t)
	store := &fakeOutboxStore{items: []OutboxEmail{item}}
	const leakedRecipient = "alice@example.test"
	sender := &fakeSender{err: &SMTPError{
		Category: SMTPErrorTransport, Operation: "closing SMTP DATA", Permanent: false,
		Err: &textproto.Error{Code: 451, Msg: "temporary failure for " + leakedRecipient},
	}}
	dispatcher, err := newDispatcher(store, sender, DispatcherOptions{
		WorkerID: "worker-1", MasterKeys: map[string][]byte{"primary": testKey}, Clock: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("newDispatcher: %v", err)
	}
	processed, err := dispatcher.DispatchOnce(context.Background())
	if processed != 0 || err == nil || len(store.failed) != 1 || len(store.rejected) != 0 {
		t.Fatalf("processed=%d err=%v failed=%d rejected=%d", processed, err, len(store.failed), len(store.rejected))
	}
	if store.failureText != "SMTP transport failure" {
		t.Fatalf("failure=%q", store.failureText)
	}
	if strings.Contains(err.Error(), leakedRecipient) || strings.Contains(err.Error(), "451") || strings.Contains(err.Error(), "temporary failure") {
		t.Fatalf("dispatcher returned raw SMTP response: %q", err)
	}
}

func TestSMTPProtocolFailureClassification(t *testing.T) {
	err := smtpProtocolFailure(SMTPErrorRecipient, "sending recipient", &textproto.Error{Code: 550, Msg: "rejected"})
	category, permanent := SMTPErrorDetails(err)
	if category != SMTPErrorRecipient || !permanent {
		t.Fatalf("category=%q permanent=%v", category, permanent)
	}
	err = smtpProtocolFailure(SMTPErrorTransport, "sending data", &textproto.Error{Code: 451, Msg: "try later"})
	category, permanent = SMTPErrorDetails(err)
	if category != SMTPErrorTransport || permanent {
		t.Fatalf("category=%q permanent=%v", category, permanent)
	}
}

func TestSMTPValidationRejectsHeaderInjection(t *testing.T) {
	_, err := NewSMTPSender(SMTPOptions{
		Host: "smtp.example.test", Port: 587, TLSMode: SMTPTLSStartTLS,
		FromAddress: "noreply@example.test", FromName: "Nyauth\r\nBcc: attacker@example.test",
	})
	if err == nil {
		t.Fatal("SMTP sender accepted an injected From header")
	}
	if err := validateEmailMessage(EmailMessage{To: "alice@example.test", Subject: "ok\r\nBcc: attacker@example.test", TextBody: "body"}); err == nil {
		t.Fatal("email message accepted an injected Subject header")
	}
}

func TestBuildMIMEMessageProducesParseableMultipartMessage(t *testing.T) {
	from := &mail.Address{Name: "Nyauth", Address: "noreply@example.test"}
	recipient := &mail.Address{Address: "alice@example.test"}
	payload, err := buildMIMEMessage(from, recipient, EmailMessage{
		To: recipient.Address, Subject: "验证邮箱", TextBody: "纯文本", HTMLBody: "<p>HTML</p>",
	})
	if err != nil {
		t.Fatalf("buildMIMEMessage: %v", err)
	}
	parsed, err := mail.ReadMessage(strings.NewReader(string(payload)))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v\n%s", err, payload)
	}
	if !strings.HasPrefix(parsed.Header.Get("Content-Type"), "multipart/alternative") {
		t.Fatalf("Content-Type = %q", parsed.Header.Get("Content-Type"))
	}
	if parsed.Header.Get("From") == "" || parsed.Header.Get("To") == "" || parsed.Header.Get("Subject") == "" {
		t.Fatalf("missing required MIME headers: %#v", parsed.Header)
	}
}
