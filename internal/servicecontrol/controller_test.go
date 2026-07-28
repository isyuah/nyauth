package servicecontrol

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Time() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

func newTestController(t *testing.T) (*Controller, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Date(2026, time.July, 28, 8, 0, 0, 0, time.UTC)}
	controller := NewController(ControllerOptions{Clock: clock.Time, StaleAfter: 15 * time.Second})
	if err := controller.Apply(t.Context(), testSnapshot(clock, 1)); err != nil {
		t.Fatalf("apply initial snapshot: %v", err)
	}
	controller.MarkHeartbeat(clock.Time())
	return controller, clock
}

func testSnapshot(clock *testClock, revision int64) Snapshot {
	now := clock.Time()
	return Snapshot{Revision: revision, UpdatedAt: now, DatabaseNow: now, ObservedAt: now}
}

func TestControllerAcquireReleaseAndCombinationAtomicity(t *testing.T) {
	controller, _ := newTestController(t)
	lease, err := controller.AcquireAll(CapabilityMediaWrites, CapabilityAccountMutations, CapabilityMediaWrites)
	if err != nil {
		t.Fatalf("acquire capabilities: %v", err)
	}
	for _, capability := range []Capability{CapabilityAccountMutations, CapabilityMediaWrites} {
		if count, _ := controller.InFlight(capability); count != 1 {
			t.Fatalf("%s in-flight = %d, want 1", capability, count)
		}
	}
	lease.Release()
	lease.Release()
	for _, capability := range []Capability{CapabilityAccountMutations, CapabilityMediaWrites} {
		if count, _ := controller.InFlight(capability); count != 0 {
			t.Fatalf("%s in-flight after idempotent release = %d", capability, count)
		}
	}

	snapshot := testSnapshot(&testClock{now: time.Date(2026, time.July, 28, 8, 0, 0, 0, time.UTC)}, 2)
	snapshot.PausedCapabilities = []Capability{CapabilityAdminMutations}
	if err := controller.Apply(t.Context(), snapshot); err != nil {
		t.Fatalf("pause admin mutations: %v", err)
	}
	if _, err := controller.AcquireAll(CapabilityAccountMutations, CapabilityAdminMutations); !errors.Is(err, ErrCapabilityPaused) {
		t.Fatalf("mixed acquisition error = %v, want ErrCapabilityPaused", err)
	}
	if count, _ := controller.InFlight(CapabilityAccountMutations); count != 0 {
		t.Fatalf("partially acquired account_mutations: %d", count)
	}
}

func TestControllerChangesPublishesAndReplacesNotificationChannel(t *testing.T) {
	controller, clock := newTestController(t)
	changes := controller.Changes()
	if err := controller.Apply(t.Context(), testSnapshot(clock, 2)); err != nil {
		t.Fatalf("apply revision 2: %v", err)
	}
	select {
	case <-changes:
	default:
		t.Fatal("state publication did not close the change channel")
	}
	next := controller.Changes()
	if next == changes {
		t.Fatal("change channel was not replaced after publication")
	}
	select {
	case <-next:
		t.Fatal("replacement change channel was already closed")
	default:
	}
}

func TestControllerClosesBeforeDrainAndConfirmsAfterRelease(t *testing.T) {
	controller, clock := newTestController(t)
	lease, err := controller.Acquire(CapabilityAuthIssuance)
	if err != nil {
		t.Fatalf("acquire old work: %v", err)
	}

	applyCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	applyDone := make(chan error, 1)
	go func() {
		snapshot := testSnapshot(clock, 2)
		snapshot.PausedCapabilities = []Capability{
			CapabilitySelfRegistration, CapabilityAuthIssuance,
		}
		applyDone <- controller.Apply(applyCtx, snapshot)
	}()

	deadline := time.Now().Add(time.Second)
	for controller.Snapshot().Revision != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if controller.Snapshot().Revision != 2 {
		t.Fatal("new revision was not published before drain")
	}
	if _, err := controller.Acquire(CapabilityAuthIssuance); !errors.Is(err, ErrCapabilityPaused) {
		t.Fatalf("new work entered closing gate: %v", err)
	}
	loaded, applied := controller.Revisions()
	if loaded != 2 || applied != 1 {
		t.Fatalf("revisions while draining = loaded %d applied %d, want 2/1", loaded, applied)
	}
	select {
	case err := <-applyDone:
		t.Fatalf("Apply returned before old work drained: %v", err)
	default:
	}

	lease.Release()
	if err := <-applyDone; err != nil {
		t.Fatalf("Apply after release: %v", err)
	}
	loaded, applied = controller.Revisions()
	if loaded != 2 || applied != 2 {
		t.Fatalf("revisions after drain = loaded %d applied %d, want 2/2", loaded, applied)
	}
}

func TestControllerApplyTimeoutStillConfirmsAfterLateRelease(t *testing.T) {
	controller, _ := newTestController(t)
	lease, err := controller.Acquire(CapabilityMailDelivery)
	if err != nil {
		t.Fatalf("acquire mail delivery: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	snapshot := testSnapshot(&testClock{now: time.Date(2026, time.July, 28, 8, 0, 0, 0, time.UTC)}, 2)
	snapshot.PausedCapabilities = []Capability{CapabilityMailDelivery}
	err = controller.Apply(ctx, snapshot)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Apply error = %v, want deadline", err)
	}
	lease.Release()
	if err := controller.WaitApplied(t.Context(), 2); err != nil {
		t.Fatalf("late drain did not confirm revision: %v", err)
	}
}

func TestControllerExpirationAndFailClosed(t *testing.T) {
	controller, clock := newTestController(t)
	expires := clock.Time().Add(time.Minute)
	snapshot := testSnapshot(clock, 2)
	snapshot.PausedCapabilities = []Capability{CapabilityMediaWrites}
	snapshot.ExpiresAt = &expires
	if err := controller.Apply(t.Context(), snapshot); err != nil {
		t.Fatalf("apply expiring pause: %v", err)
	}
	if _, err := controller.Acquire(CapabilityMediaWrites); !errors.Is(err, ErrCapabilityPaused) {
		t.Fatalf("acquire before expiration error = %v", err)
	}
	clock.Advance(time.Minute)
	refreshed := testSnapshot(clock, 2)
	refreshed.PausedCapabilities = []Capability{CapabilityMediaWrites}
	refreshed.ExpiresAt = &expires
	refreshed.UpdatedAt = snapshot.UpdatedAt
	// Reconciliation observes the same PostgreSQL revision and refreshes the
	// database-clock calibration before the exact expiry instant.
	refreshed.DatabaseNow = expires
	if err := controller.Apply(t.Context(), refreshed); err != nil {
		t.Fatalf("reconcile at expiration: %v", err)
	}
	controller.MarkHeartbeat(clock.Time())
	lease, err := controller.Acquire(CapabilityMediaWrites)
	if err != nil {
		t.Fatalf("local expiration did not reopen gate: %v", err)
	}
	lease.Release()
	if snapshot := controller.Snapshot(); len(snapshot.PausedCapabilities) != 0 || snapshot.ExpiresAt != nil {
		t.Fatalf("effective expired snapshot = %#v", snapshot)
	}

	clock.Advance(15 * time.Second)
	if _, err := controller.Acquire(CapabilityAccountMutations); !errors.Is(err, ErrCapabilityPaused) {
		t.Fatalf("stale controller error = %v, want fail-closed", err)
	} else {
		var paused *PausedError
		if !errors.As(err, &paused) || !paused.FailClosed {
			t.Fatalf("stale controller error = %#v, want fail-closed detail", err)
		}
	}
	if err := controller.Apply(t.Context(), testSnapshot(clock, 3)); err != nil {
		t.Fatalf("refresh controller: %v", err)
	}
	if _, err := controller.Acquire(CapabilityAccountMutations); !errors.Is(err, ErrCapabilityPaused) {
		t.Fatalf("stale heartbeat did not remain fail-closed: %v", err)
	}
	controller.MarkHeartbeat(clock.Time())
	lease, err = controller.Acquire(CapabilityAccountMutations)
	if err != nil {
		t.Fatalf("fresh heartbeat and state did not reopen: %v", err)
	}
	lease.Release()
}

func TestControllerExpirationUsesCalibratedDatabaseClock(t *testing.T) {
	local := &testClock{now: time.Date(2026, time.July, 28, 8, 0, 0, 0, time.UTC)}
	controller := NewController(ControllerOptions{Clock: local.Time, StaleAfter: 10 * time.Minute})
	databaseNow := local.Time().Add(2 * time.Hour)
	expires := databaseNow.Add(time.Minute)
	snapshot := Snapshot{
		Revision: 1, PausedCapabilities: []Capability{CapabilityAuthIssuance},
		ExpiresAt: &expires, UpdatedAt: databaseNow,
		DatabaseNow: databaseNow, ObservedAt: local.Time(),
	}
	if err := controller.Apply(t.Context(), snapshot); err != nil {
		t.Fatalf("apply skewed database snapshot: %v", err)
	}
	controller.MarkHeartbeat(local.Time())
	if _, err := controller.Acquire(CapabilityAuthIssuance); !errors.Is(err, ErrCapabilityPaused) {
		t.Fatalf("capability before database expiration error = %v", err)
	}
	local.Advance(time.Minute)
	lease, err := controller.Acquire(CapabilityAuthIssuance)
	if err != nil {
		t.Fatalf("database-clock expiration did not reopen capability: %v", err)
	}
	lease.Release()
}

func TestControllerRejectsUnknownAndConflictingRevisions(t *testing.T) {
	controller, _ := newTestController(t)
	if _, err := controller.Acquire(Capability("future")); !errors.Is(err, ErrUnknownCapability) {
		t.Fatalf("unknown acquisition error = %v", err)
	}
	invalid := testSnapshot(&testClock{now: time.Now().UTC()}, 0)
	if err := controller.Apply(t.Context(), invalid); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("zero revision error = %v", err)
	}
	clock := &testClock{now: time.Date(2026, time.July, 28, 8, 0, 0, 0, time.UTC)}
	if err := controller.Apply(t.Context(), testSnapshot(clock, 2)); err != nil {
		t.Fatalf("apply revision 2: %v", err)
	}
	if err := controller.Apply(t.Context(), testSnapshot(clock, 1)); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale revision error = %v", err)
	}
	conflicting := testSnapshot(clock, 2)
	conflicting.PublicMessage = "different"
	if err := controller.Apply(t.Context(), conflicting); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("same revision conflict error = %v", err)
	}
}

func TestManagerFailClosedDelegatesToController(t *testing.T) {
	controller, clock := newTestController(t)
	manager := &Manager{controller: controller}
	if manager.FailClosed() {
		t.Fatal("fresh manager reported fail-closed")
	}
	clock.Advance(15 * time.Second)
	if !manager.FailClosed() {
		t.Fatal("stale manager did not report fail-closed")
	}
	var nilManager *Manager
	if !nilManager.FailClosed() {
		t.Fatal("nil manager must fail closed")
	}
}
