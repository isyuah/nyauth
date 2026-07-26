package account

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeOutboxStore struct {
	items       []OutboxEmail
	sent        []uuid.UUID
	failed      []uuid.UUID
	failureText string
	retryAt     time.Time
	backlog     int64
}

func (f *fakeOutboxStore) EmailOutboxBacklog(context.Context, time.Time) (int64, error) {
	return f.backlog, nil
}

func (f *fakeOutboxStore) ClaimEmailBatch(context.Context, string, int, time.Time, time.Duration) ([]OutboxEmail, error) {
	return f.items, nil
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

type fakeSender struct {
	messages []EmailMessage
	err      error
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
	dispatcher, err := newDispatcher(store, sender, DispatcherOptions{
		WorkerID: "worker-1", MasterKeys: map[string][]byte{"primary": testKey}, Clock: func() time.Time { return testNow },
		OnDelivery: func(_ context.Context, currentResult string, retry bool) {
			result, retryScheduled = currentResult, retry
		},
		OnBacklog: func(_ context.Context, currentBacklog int64) { backlog = currentBacklog },
	})
	if err != nil {
		t.Fatalf("newDispatcher: %v", err)
	}
	_, _ = dispatcher.DispatchOnce(context.Background())
	if result != "failure" || !retryScheduled || backlog != 3 {
		t.Fatalf("result=%q retry=%v backlog=%d", result, retryScheduled, backlog)
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
