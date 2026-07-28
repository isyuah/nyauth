package securityrevocation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type dispatcherTestStore struct {
	tasks     []Task
	completed bool
	retried   bool
	retryAt   time.Time
	lastError string
}

func (s *dispatcherTestStore) Claim(context.Context, string, int, time.Time, time.Duration) ([]Task, error) {
	return append([]Task(nil), s.tasks...), nil
}
func (s *dispatcherTestStore) Complete(context.Context, Task, string, time.Time) (bool, error) {
	return s.completed, nil
}
func (s *dispatcherTestStore) Retry(_ context.Context, _ Task, _ string, lastError string, retryAt, _ time.Time) error {
	s.retried, s.retryAt, s.lastError = true, retryAt, lastError
	return nil
}

type dispatcherTestCleaner struct {
	fullSessions, staleSessions int
	fullRefresh, staleRefresh   int
	sessionErr, refreshErr      error
}

func (c *dispatcherTestCleaner) DeleteUserSessions(context.Context, string) (int64, error) {
	c.fullSessions++
	return 0, c.sessionErr
}
func (c *dispatcherTestCleaner) DeleteUserSessionsBeforeSecurityVersion(context.Context, string, int64, int64) (int64, error) {
	c.staleSessions++
	return 0, c.sessionErr
}
func (c *dispatcherTestCleaner) RevokeRefreshFamiliesForUser(context.Context, string, time.Duration) (int64, error) {
	c.fullRefresh++
	return 0, c.refreshErr
}
func (c *dispatcherTestCleaner) RevokeRefreshFamiliesBeforeAuthVersion(context.Context, string, int64, time.Duration) (int64, error) {
	c.staleRefresh++
	return 0, c.refreshErr
}

func TestDispatcherUsesGenerationAwareAndDeletionCleanup(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		task      Task
		wantFull  int
		wantStale int
	}{
		{name: "generation update", task: Task{UserID: uuid.New(), Revision: 1, AuthVersion: 3, SessionVersion: 4, AttemptCount: 1}, wantStale: 2},
		{name: "deleted user", task: Task{UserID: uuid.New(), Revision: 1, AuthVersion: 3, SessionVersion: 4, UserDeleted: true, AttemptCount: 1}, wantFull: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &dispatcherTestStore{tasks: []Task{test.task}, completed: true}
			cleaner := &dispatcherTestCleaner{}
			dispatcher, err := newDispatcher(store, cleaner, DispatcherOptions{
				WorkerID: "test-worker", RefreshTokenTTL: time.Hour, Clock: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			processed, err := dispatcher.DispatchOnce(context.Background())
			if err != nil || processed != 1 {
				t.Fatalf("DispatchOnce() processed=%d err=%v", processed, err)
			}
			full := cleaner.fullSessions + cleaner.fullRefresh
			stale := cleaner.staleSessions + cleaner.staleRefresh
			if full != test.wantFull || stale != test.wantStale {
				t.Fatalf("cleanup calls full=%d stale=%d, want full=%d stale=%d", full, stale, test.wantFull, test.wantStale)
			}
		})
	}
}

func TestDispatcherRetriesCombinedCleanupFailureAndDoesNotCountSupersededTask(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	task := Task{UserID: uuid.New(), Revision: 4, AuthVersion: 5, SessionVersion: 2, AttemptCount: 3}
	store := &dispatcherTestStore{tasks: []Task{task}}
	cleaner := &dispatcherTestCleaner{sessionErr: errors.New("session cleanup unavailable"), refreshErr: errors.New("refresh cleanup unavailable")}
	dispatcher, err := newDispatcher(store, cleaner, DispatcherOptions{
		WorkerID: "test-worker", RefreshTokenTTL: time.Hour, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	processed, err := dispatcher.DispatchOnce(context.Background())
	if err == nil || processed != 0 || !store.retried {
		t.Fatalf("failed cleanup processed=%d retried=%v err=%v", processed, store.retried, err)
	}
	if cleaner.staleSessions != 1 || cleaner.staleRefresh != 1 {
		t.Fatalf("both idempotent cleanup paths were not attempted: %#v", cleaner)
	}
	if !errors.Is(err, cleaner.sessionErr) || !errors.Is(err, cleaner.refreshErr) {
		t.Fatalf("combined cleanup error lost a cause: %v", err)
	}
	if store.retryAt != now.Add(4*time.Second) {
		t.Fatalf("retryAt=%s, want %s", store.retryAt, now.Add(4*time.Second))
	}

	store = &dispatcherTestStore{tasks: []Task{task}, completed: false}
	cleaner = &dispatcherTestCleaner{}
	dispatcher, err = newDispatcher(store, cleaner, DispatcherOptions{
		WorkerID: "test-worker", RefreshTokenTTL: time.Hour, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	processed, err = dispatcher.DispatchOnce(context.Background())
	if err != nil || processed != 0 {
		t.Fatalf("superseded task processed=%d err=%v", processed, err)
	}
}
