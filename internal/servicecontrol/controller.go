package servicecontrol

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const DefaultStaleAfter = 15 * time.Second

type ControllerOptions struct {
	Clock      func() time.Time
	StaleAfter time.Duration
}

// Controller owns process-local gates. A single lock makes checking and
// acquiring multiple capabilities atomic with respect to revision changes.
type Controller struct {
	mu              sync.Mutex
	now             func() time.Time
	staleAfter      time.Duration
	snapshot        Snapshot
	loaded          bool
	lastRefresh     time.Time
	lastHeartbeat   time.Time
	databaseAnchor  time.Time
	localAnchor     time.Time
	inFlight        map[Capability]int64
	loadedRevision  int64
	appliedRevision int64
	changed         chan struct{}
}

func NewController(options ControllerOptions) *Controller {
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.StaleAfter <= 0 {
		options.StaleAfter = DefaultStaleAfter
	}
	now := options.Clock().UTC()
	return &Controller{
		now: options.Clock, staleAfter: options.StaleAfter,
		lastRefresh: now, lastHeartbeat: now,
		inFlight: make(map[Capability]int64), changed: make(chan struct{}),
	}
}

type Lease struct {
	controller   *Controller
	capabilities []Capability
	once         sync.Once
}

func (l *Lease) Release() {
	if l == nil || l.controller == nil {
		return
	}
	l.once.Do(func() { l.controller.release(l.capabilities) })
}

func (c *Controller) Acquire(capability Capability) (*Lease, error) {
	return c.AcquireAll(capability)
}

func (c *Controller) AcquireAll(capabilities ...Capability) (*Lease, error) {
	normalized, err := NormalizeCapabilities(capabilities)
	if err != nil {
		return nil, err
	}
	if len(normalized) == 0 {
		return &Lease{}, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	databaseNow := c.databaseNowLocked(now)
	effective := c.snapshot.EffectiveAt(databaseNow)
	failClosed := c.failClosedLocked(now)
	blocked := make([]Capability, 0, len(normalized))
	for _, capability := range normalized {
		if failClosed || containsCapability(effective.PausedCapabilities, capability) {
			blocked = append(blocked, capability)
		}
	}
	if len(blocked) > 0 {
		return nil, &PausedError{
			Capabilities: blocked,
			RetryAfter:   retryAfter(effective.ExpiresAt, databaseNow),
			ExpiresAt:    effective.ExpiresAt,
			FailClosed:   failClosed,
		}
	}
	for _, capability := range normalized {
		c.inFlight[capability]++
	}
	return &Lease{controller: c, capabilities: normalized}, nil
}

func (c *Controller) release(capabilities []Capability) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, capability := range capabilities {
		if c.inFlight[capability] <= 1 {
			delete(c.inFlight, capability)
		} else {
			c.inFlight[capability]--
		}
	}
	c.maybeMarkAppliedLocked(c.now().UTC())
	c.signalLocked()
}

// Apply publishes the new gates before waiting for work admitted by the old
// revision. A deadline only bounds the caller's wait; Release will still mark
// the revision applied after the final old lease drains.
func (c *Controller) Apply(ctx context.Context, snapshot Snapshot) error {
	if err := c.publish(snapshot); err != nil {
		return err
	}
	return c.WaitApplied(ctx, snapshot.Revision)
}

// publish closes the new gates synchronously without waiting for work admitted
// by the previous revision. Manager uses this split to report loaded_revision
// immediately while it waits for local and remote instances to drain.
func (c *Controller) publish(snapshot Snapshot) error {
	normalized, err := validateSnapshot(snapshot)
	if err != nil {
		return err
	}
	snapshot.PausedCapabilities = normalized
	snapshot = cloneSnapshot(snapshot)

	c.mu.Lock()
	localNow := c.now().UTC()
	if c.loaded && snapshot.Revision < c.loadedRevision {
		c.mu.Unlock()
		return fmt.Errorf("%w: loaded %d, received %d", ErrStaleRevision, c.loadedRevision, snapshot.Revision)
	}
	if c.loaded && snapshot.Revision == c.loadedRevision && !sameSnapshot(c.snapshot, snapshot) {
		c.mu.Unlock()
		return fmt.Errorf("%w: revision %d has conflicting content", ErrInvalidState, snapshot.Revision)
	}
	c.snapshot = snapshot
	c.loaded = true
	c.loadedRevision = snapshot.Revision
	// Carry PostgreSQL time forward using elapsed local time. Reconciliation
	// replaces this anchor every five seconds, bounding drift without trusting
	// the host wall clock for the actual expiry comparison.
	estimatedDatabaseNow := snapshot.DatabaseNow.Add(localNow.Sub(snapshot.ObservedAt))
	c.databaseAnchor = estimatedDatabaseNow
	c.localAnchor = localNow
	c.lastRefresh = localNow
	c.maybeMarkAppliedLocked(c.lastRefresh)
	c.signalLocked()
	c.mu.Unlock()
	return nil
}

func (c *Controller) WaitApplied(ctx context.Context, revision int64) error {
	for {
		c.mu.Lock()
		if c.loadedRevision > revision {
			c.mu.Unlock()
			return fmt.Errorf("%w: waiting for %d, loaded %d", ErrSuperseded, revision, c.loadedRevision)
		}
		if c.appliedRevision >= revision {
			c.mu.Unlock()
			return nil
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

// MarkHeartbeat records the local time at which this instance successfully
// updated its database liveness row. Both heartbeat and state refresh must
// remain fresh; PostgreSQL timestamps are not mixed with this local duration.
func (c *Controller) MarkHeartbeat(at time.Time) {
	c.mu.Lock()
	if at.UTC().After(c.lastHeartbeat) {
		c.lastHeartbeat = at.UTC()
	}
	c.signalLocked()
	c.mu.Unlock()
}

func (c *Controller) MarkHeartbeatNow() {
	c.MarkHeartbeat(c.now())
}

// MarkRefreshed keeps a same-revision reconciliation fresh without reopening
// gates or changing revision bookkeeping.
func (c *Controller) MarkRefreshed(at time.Time) {
	c.mu.Lock()
	if at.UTC().After(c.lastRefresh) {
		c.lastRefresh = at.UTC()
	}
	c.signalLocked()
	c.mu.Unlock()
}

func (c *Controller) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	c.maybeMarkAppliedLocked(now)
	return c.snapshot.EffectiveAt(c.databaseNowLocked(now))
}

// Changes returns a channel that is closed the next time the controller's
// observable state may have changed. Callers must obtain a new channel after
// every notification.
func (c *Controller) Changes() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.changed
}

func (c *Controller) Revisions() (loaded, applied int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maybeMarkAppliedLocked(c.now().UTC())
	return c.loadedRevision, c.appliedRevision
}

func (c *Controller) FailClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failClosedLocked(c.now().UTC())
}

func (c *Controller) InFlight(capability Capability) (int64, error) {
	if !capability.Valid() {
		return 0, fmt.Errorf("%w: %q", ErrUnknownCapability, capability)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inFlight[capability], nil
}

func (c *Controller) failClosedLocked(now time.Time) bool {
	return !c.loaded || now.Sub(c.lastRefresh) >= c.staleAfter || now.Sub(c.lastHeartbeat) >= c.staleAfter
}

func (c *Controller) maybeMarkAppliedLocked(now time.Time) {
	if !c.loaded {
		return
	}
	effective := c.snapshot.EffectiveAt(c.databaseNowLocked(now))
	for _, capability := range effective.PausedCapabilities {
		if c.inFlight[capability] > 0 {
			return
		}
	}
	c.appliedRevision = c.loadedRevision
}

func (c *Controller) signalLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

func validateSnapshot(snapshot Snapshot) ([]Capability, error) {
	if snapshot.Revision < 1 {
		return nil, fmt.Errorf("%w: revision must be positive", ErrInvalidState)
	}
	if snapshot.DatabaseNow.IsZero() || snapshot.ObservedAt.IsZero() {
		return nil, fmt.Errorf("%w: database clock observation is required", ErrInvalidState)
	}
	return NormalizeCapabilities(snapshot.PausedCapabilities)
}

func (c *Controller) databaseNowLocked(localNow time.Time) time.Time {
	if c.databaseAnchor.IsZero() || c.localAnchor.IsZero() {
		return time.Time{}
	}
	return c.databaseAnchor.Add(localNow.Sub(c.localAnchor))
}

func sameSnapshot(left, right Snapshot) bool {
	if left.Revision != right.Revision || left.PublicMessage != right.PublicMessage ||
		left.InternalReason != right.InternalReason || left.UpdatedAt != right.UpdatedAt {
		return false
	}
	if !equalTimePointers(left.ExpiresAt, right.ExpiresAt) || len(left.PausedCapabilities) != len(right.PausedCapabilities) {
		return false
	}
	for index := range left.PausedCapabilities {
		if left.PausedCapabilities[index] != right.PausedCapabilities[index] {
			return false
		}
	}
	return true
}

func equalTimePointers(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func containsCapability(values []Capability, target Capability) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func retryAfter(expiresAt *time.Time, now time.Time) time.Duration {
	if expiresAt == nil {
		return time.Minute
	}
	remaining := expiresAt.Sub(now)
	if remaining <= 0 {
		return 0
	}
	return remaining
}
