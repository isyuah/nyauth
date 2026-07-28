package securityrevocation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type taskStore interface {
	Claim(context.Context, string, int, time.Time, time.Duration) ([]Task, error)
	Complete(context.Context, Task, string, time.Time) (bool, error)
	Retry(context.Context, Task, string, string, time.Time, time.Time) error
}

type securityStateCleaner interface {
	DeleteUserSessions(context.Context, string) (int64, error)
	DeleteUserSessionsBeforeSecurityVersion(context.Context, string, int64, int64) (int64, error)
	RevokeRefreshFamiliesForUser(context.Context, string, time.Duration) (int64, error)
	RevokeRefreshFamiliesBeforeAuthVersion(context.Context, string, int64, time.Duration) (int64, error)
}

type DispatcherOptions struct {
	WorkerID        string
	BatchSize       int
	Lease           time.Duration
	Interval        time.Duration
	RefreshTokenTTL time.Duration
	Clock           func() time.Time
	OnError         func(context.Context, Task, error)
}

type Dispatcher struct {
	store           taskStore
	cleaner         securityStateCleaner
	workerID        string
	batchSize       int
	lease           time.Duration
	interval        time.Duration
	refreshTokenTTL time.Duration
	clock           func() time.Time
	onError         func(context.Context, Task, error)
}

func NewDispatcher(store *Store, cleaner securityStateCleaner, options DispatcherOptions) (*Dispatcher, error) {
	return newDispatcher(store, cleaner, options)
}

func newDispatcher(store taskStore, cleaner securityStateCleaner, options DispatcherOptions) (*Dispatcher, error) {
	options.WorkerID = strings.TrimSpace(options.WorkerID)
	if store == nil || cleaner == nil || options.WorkerID == "" || len(options.WorkerID) > 128 {
		return nil, fmt.Errorf("valid security revocation dispatcher dependencies are required")
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
	if options.RefreshTokenTTL <= 0 || options.BatchSize < 1 || options.BatchSize > 100 || options.Lease <= 0 || options.Interval <= 0 {
		return nil, fmt.Errorf("invalid security revocation dispatcher settings")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	return &Dispatcher{
		store: store, cleaner: cleaner, workerID: options.WorkerID,
		batchSize: options.BatchSize, lease: options.Lease, interval: options.Interval,
		refreshTokenTTL: options.RefreshTokenTTL, clock: options.Clock, onError: options.OnError,
	}, nil
}

func (d *Dispatcher) DispatchOnce(ctx context.Context) (int, error) {
	now := d.clock().UTC()
	tasks, err := d.store.Claim(ctx, d.workerID, d.batchSize, now, d.lease)
	if err != nil {
		return 0, err
	}
	processed := 0
	var dispatchErrors []error
	for _, task := range tasks {
		cleanupErr := d.clean(ctx, task)
		completed := false
		if cleanupErr == nil {
			completed, cleanupErr = d.store.Complete(ctx, task, d.workerID, d.clock().UTC())
		}
		if cleanupErr == nil {
			if completed {
				processed++
			}
			continue
		}
		retryAt := now.Add(retryDelay(task.AttemptCount))
		retryErr := d.store.Retry(ctx, task, d.workerID, cleanupErr.Error(), retryAt, d.clock().UTC())
		combined := errors.Join(cleanupErr, retryErr)
		if d.onError != nil && ctx.Err() == nil {
			d.onError(ctx, task, combined)
		}
		dispatchErrors = append(dispatchErrors, combined)
	}
	return processed, errors.Join(dispatchErrors...)
}

func (d *Dispatcher) clean(ctx context.Context, task Task) error {
	userID := task.UserID.String()
	if task.UserDeleted {
		_, sessionErr := d.cleaner.DeleteUserSessions(ctx, userID)
		_, refreshErr := d.cleaner.RevokeRefreshFamiliesForUser(ctx, userID, d.refreshTokenTTL)
		return errors.Join(sessionErr, refreshErr)
	}
	_, sessionErr := d.cleaner.DeleteUserSessionsBeforeSecurityVersion(
		ctx, userID, task.AuthVersion, task.SessionVersion,
	)
	_, refreshErr := d.cleaner.RevokeRefreshFamiliesBeforeAuthVersion(
		ctx, userID, task.AuthVersion, d.refreshTokenTTL,
	)
	return errors.Join(sessionErr, refreshErr)
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

func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 9 {
		attempt = 9
	}
	return time.Second * time.Duration(1<<(attempt-1))
}
