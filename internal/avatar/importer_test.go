package avatar

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	internalcrypto "github.com/nyasharp/nyauth/internal/crypto"
)

func TestNewProviderImportJobEncryptsURLWithBoundAAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	providerID := uuid.New()
	userID := uuid.New()
	job, err := NewProviderImportJob(key, "primary", providerID, userID, "https://images.example.test/avatar.png", time.Now())
	if err != nil {
		t.Fatalf("NewProviderImportJob() error = %v", err)
	}
	plaintext, err := internalcrypto.DecryptEnvelope(
		map[string][]byte{"primary": key}, providerAvatarURLPurpose, job.EncryptedAvatarURL,
		providerImportAAD(job.ID, providerID, userID),
	)
	if err != nil {
		t.Fatalf("DecryptEnvelope() error = %v", err)
	}
	if string(plaintext) != "https://images.example.test/avatar.png" {
		t.Fatalf("plaintext = %q", plaintext)
	}
	if _, err := internalcrypto.DecryptEnvelope(
		map[string][]byte{"primary": key}, providerAvatarURLPurpose, job.EncryptedAvatarURL,
		providerImportAAD(job.ID, providerID, uuid.New()),
	); err == nil {
		t.Fatal("job envelope decrypted for a different user")
	}
}

func TestProviderImportRetryScheduleTreatsJobTimeoutAsTransient(t *testing.T) {
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		err     error
		attempt int
		want    time.Duration
		final   bool
	}{
		{name: "first timeout", err: context.DeadlineExceeded, attempt: 1, want: time.Minute},
		{name: "second transient failure", err: errors.New("temporary transport failure"), attempt: 2, want: 5 * time.Minute},
		{name: "third transient failure", err: errors.New("temporary storage failure"), attempt: 3, want: 30 * time.Minute},
		{name: "fourth transient failure", err: errors.New("still unavailable"), attempt: 4, final: true},
		{name: "permanent failure", err: permanentImportFailure("invalid_image", ErrUnsupportedMedia), attempt: 1, final: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			retryAt := providerImportRetryAt(test.err, test.attempt, now)
			if test.final {
				if retryAt != nil {
					t.Fatalf("retryAt = %s, want final failure", retryAt)
				}
				return
			}
			if retryAt == nil || !retryAt.Equal(now.Add(test.want)) {
				t.Fatalf("retryAt = %v, want %s", retryAt, now.Add(test.want))
			}
		})
	}
}

func TestProviderImportWorkerDoesNotClaimWhileMediaWritesArePaused(t *testing.T) {
	acquired := 0
	worker := &ImportWorker{acquireWork: func() (func(), bool) {
		acquired++
		return nil, false
	}}
	if err := worker.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if acquired != 1 {
		t.Fatalf("AcquireWork calls = %d, want 1", acquired)
	}
}
