package mailruntime

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nyasharp/nyauth/internal/audit"
)

// RecordDeliveryOutcome atomically updates the HA-shared transport failure
// window. Recipient failures are intentionally ignored, permanent global
// failures open immediately, and transport failures open on the third failure
// within the two-minute window.
func (s *Store) RecordDeliveryOutcome(ctx context.Context, outcome DeliveryOutcome) (CircuitTransition, error) {
	if s == nil || s.db == nil {
		return CircuitTransition{}, ErrStoreUnavailable
	}
	if err := validateSource(outcome.Source); err != nil {
		return CircuitTransition{}, err
	}
	category, reason, err := normalizeDeliveryOutcome(outcome)
	if err != nil {
		return CircuitTransition{}, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return CircuitTransition{}, fmt.Errorf("starting mail circuit outcome transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return CircuitTransition{}, err
	}
	if !sourceMatchesState(outcome.Source, state) {
		return CircuitTransition{}, ErrStaleEffectiveConfig
	}
	transition := CircuitTransition{State: state}
	if state.CircuitState == CircuitOpen || category == ErrorCategoryRecipient {
		return transition, nil
	}

	now := s.now()
	if outcome.Success {
		if state.TransportFailureCount == 0 {
			return transition, nil
		}
		state, err = scanState(tx.QueryRow(ctx, `
			UPDATE mail_runtime_state
			SET transport_failure_window_started_at=NULL,transport_failure_count=0,
			    revision=revision+1,updated_at=$1
			WHERE singleton=TRUE
			RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,
			          circuit_state,circuit_open_reason,circuit_open_category,circuit_opened_at,
			          transport_failure_window_started_at,transport_failure_count,next_probe_at,updated_at
		`, now))
		if err != nil {
			return CircuitTransition{}, fmt.Errorf("resetting mail transport failure window: %w", err)
		}
		transition.State = state
		transition.Changed = true
		if err := notifyTx(ctx, tx, "circuit_reset", state.Revision); err != nil {
			return CircuitTransition{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return CircuitTransition{}, fmt.Errorf("committing mail circuit reset: %w", err)
		}
		return transition, nil
	}

	if category != ErrorCategoryTransport {
		state, err = scanState(tx.QueryRow(ctx, `
			UPDATE mail_runtime_state
			SET circuit_state='open',circuit_open_reason=$1,circuit_open_category=$2,
			    circuit_opened_at=$3,transport_failure_window_started_at=NULL,
			    transport_failure_count=0,next_probe_at=$4,
			    revision=revision+1,updated_at=$3
			WHERE singleton=TRUE
			RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,
			          circuit_state,circuit_open_reason,circuit_open_category,circuit_opened_at,
			          transport_failure_window_started_at,transport_failure_count,next_probe_at,updated_at
		`, reason, category, now, now.Add(CircuitProbeInterval)))
		if err != nil {
			return CircuitTransition{}, fmt.Errorf("opening mail circuit: %w", err)
		}
		if err := enqueueCircuitOpenedTx(ctx, tx, outcome.Source, category, reason, now); err != nil {
			return CircuitTransition{}, err
		}
		transition.State = state
		transition.Changed = true
		transition.Opened = true
		if err := notifyTx(ctx, tx, "circuit_opened", state.Revision); err != nil {
			return CircuitTransition{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return CircuitTransition{}, fmt.Errorf("committing open mail circuit: %w", err)
		}
		return transition, nil
	}

	windowStarted := state.TransportFailureWindowStarted
	failureCount := state.TransportFailureCount
	if windowStarted == nil || now.Before(*windowStarted) || now.Sub(*windowStarted) > TransportFailureWindow {
		windowStarted = &now
		failureCount = 0
	}
	failureCount++
	opened := failureCount >= TransportFailureLimit
	if opened {
		state, err = scanState(tx.QueryRow(ctx, `
			UPDATE mail_runtime_state
			SET circuit_state='open',circuit_open_reason=$1,circuit_open_category='transport',
			    circuit_opened_at=$2,transport_failure_window_started_at=$3,
			    transport_failure_count=$4,next_probe_at=$5,
			    revision=revision+1,updated_at=$2
			WHERE singleton=TRUE
			RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,
			          circuit_state,circuit_open_reason,circuit_open_category,circuit_opened_at,
			          transport_failure_window_started_at,transport_failure_count,next_probe_at,updated_at
		`, reason, now, windowStarted, failureCount, now.Add(CircuitProbeInterval)))
		if err != nil {
			return CircuitTransition{}, fmt.Errorf("opening mail transport circuit: %w", err)
		}
		if err := enqueueCircuitOpenedTx(ctx, tx, outcome.Source, category, reason, now); err != nil {
			return CircuitTransition{}, err
		}
	} else {
		state, err = scanState(tx.QueryRow(ctx, `
			UPDATE mail_runtime_state
			SET transport_failure_window_started_at=$1,transport_failure_count=$2,
			    revision=revision+1,updated_at=$3
			WHERE singleton=TRUE
			RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,
			          circuit_state,circuit_open_reason,circuit_open_category,circuit_opened_at,
			          transport_failure_window_started_at,transport_failure_count,next_probe_at,updated_at
		`, windowStarted, failureCount, now))
		if err != nil {
			return CircuitTransition{}, fmt.Errorf("recording mail transport failure: %w", err)
		}
	}
	transition.State = state
	transition.Changed = true
	transition.Opened = opened
	kind := "circuit_failure"
	if opened {
		kind = "circuit_opened"
	}
	if err := notifyTx(ctx, tx, kind, state.Revision); err != nil {
		return CircuitTransition{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CircuitTransition{}, fmt.Errorf("committing mail transport outcome: %w", err)
	}
	return transition, nil
}

// ClaimProbe advances next_probe_at while holding the singleton row lock. The
// returned revision must be supplied to RecordProbeOutcome, preventing a stale
// probe from closing a circuit after configuration or state changed.
func (s *Store) ClaimProbe(ctx context.Context, source EffectiveSource) (ProbeClaim, error) {
	if s == nil || s.db == nil {
		return ProbeClaim{}, ErrStoreUnavailable
	}
	if err := validateSource(source); err != nil {
		return ProbeClaim{}, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return ProbeClaim{}, fmt.Errorf("starting mail circuit probe claim: %w", err)
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return ProbeClaim{}, err
	}
	if !sourceMatchesState(source, state) {
		return ProbeClaim{}, ErrStaleEffectiveConfig
	}
	if state.CircuitState != CircuitOpen {
		return ProbeClaim{State: state}, ErrCircuitClosed
	}
	now := s.now()
	if state.NextProbeAt == nil || now.Before(*state.NextProbeAt) {
		return ProbeClaim{State: state}, ErrProbeNotDue
	}
	state, err = scanState(tx.QueryRow(ctx, `
		UPDATE mail_runtime_state
		SET next_probe_at=$1,revision=revision+1,updated_at=$2
		WHERE singleton=TRUE
		RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,
		          circuit_state,circuit_open_reason,circuit_open_category,circuit_opened_at,
		          transport_failure_window_started_at,transport_failure_count,next_probe_at,updated_at
	`, now.Add(CircuitProbeInterval), now))
	if err != nil {
		return ProbeClaim{}, fmt.Errorf("claiming mail circuit probe: %w", err)
	}
	if err := notifyTx(ctx, tx, "probe_claimed", state.Revision); err != nil {
		return ProbeClaim{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ProbeClaim{}, fmt.Errorf("committing mail circuit probe claim: %w", err)
	}
	return ProbeClaim{Acquired: true, ExpectedRevision: state.Revision, State: state}, nil
}

func (s *Store) RecordProbeOutcome(ctx context.Context, outcome ProbeOutcome) (CircuitTransition, error) {
	if s == nil || s.db == nil {
		return CircuitTransition{}, ErrStoreUnavailable
	}
	if outcome.ExpectedRevision < 0 {
		return CircuitTransition{}, fmt.Errorf("%w: expected revision must be nonnegative", ErrInvalidOutcome)
	}
	if err := validateSource(outcome.Source); err != nil {
		return CircuitTransition{}, err
	}
	category, reason, err := normalizeProbeOutcome(outcome)
	if err != nil {
		return CircuitTransition{}, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return CircuitTransition{}, fmt.Errorf("starting mail circuit probe outcome: %w", err)
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return CircuitTransition{}, err
	}
	if err := requireRevision(state, outcome.ExpectedRevision); err != nil {
		return CircuitTransition{}, err
	}
	if !sourceMatchesState(outcome.Source, state) {
		return CircuitTransition{}, ErrStaleEffectiveConfig
	}
	if state.CircuitState != CircuitOpen {
		return CircuitTransition{}, ErrCircuitClosed
	}
	now := s.now()
	transition := CircuitTransition{Changed: true}
	if outcome.Success {
		targetID := sourceTargetID(outcome.Source)
		state, err = scanState(tx.QueryRow(ctx, `
			UPDATE mail_runtime_state
			SET circuit_state='closed',circuit_open_reason=NULL,circuit_open_category=NULL,
			    circuit_opened_at=NULL,transport_failure_window_started_at=NULL,
			    transport_failure_count=0,next_probe_at=NULL,
			    revision=revision+1,updated_at=$1
			WHERE singleton=TRUE
			RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,
			          circuit_state,circuit_open_reason,circuit_open_category,circuit_opened_at,
			          transport_failure_window_started_at,transport_failure_count,next_probe_at,updated_at
		`, now))
		if err != nil {
			return CircuitTransition{}, fmt.Errorf("recovering mail circuit: %w", err)
		}
		if err := enqueueCircuitRecoveredTx(ctx, tx, targetID, "probe_succeeded", now); err != nil {
			return CircuitTransition{}, err
		}
		transition.Recovered = true
	} else {
		_ = category
		_ = reason
		state, err = scanState(tx.QueryRow(ctx, `
			UPDATE mail_runtime_state
			SET next_probe_at=$1,revision=revision+1,updated_at=$2
			WHERE singleton=TRUE
			RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,
			          circuit_state,circuit_open_reason,circuit_open_category,circuit_opened_at,
			          transport_failure_window_started_at,transport_failure_count,next_probe_at,updated_at
		`, now.Add(CircuitProbeInterval), now))
		if err != nil {
			return CircuitTransition{}, fmt.Errorf("recording failed mail circuit probe: %w", err)
		}
	}
	transition.State = state
	kind := "probe_failed"
	if transition.Recovered {
		kind = "circuit_recovered"
	}
	if err := notifyTx(ctx, tx, kind, state.Revision); err != nil {
		return CircuitTransition{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CircuitTransition{}, fmt.Errorf("committing mail circuit probe outcome: %w", err)
	}
	return transition, nil
}

func validateSource(source EffectiveSource) error {
	switch source.Mode {
	case ModeFallback:
		if source.VersionID != nil {
			return fmt.Errorf("%w: fallback source cannot have a version", ErrInvalidOutcome)
		}
	case ModeActive:
		if source.VersionID == nil {
			return fmt.Errorf("%w: active source requires a version", ErrInvalidOutcome)
		}
	default:
		return fmt.Errorf("%w: effective source mode is invalid", ErrInvalidOutcome)
	}
	return nil
}

func sourceMatchesState(source EffectiveSource, state State) bool {
	if source.Mode != state.Mode {
		return false
	}
	if source.Mode == ModeFallback {
		return state.ActiveVersionID == nil
	}
	return source.VersionID != nil && state.ActiveVersionID != nil && *source.VersionID == *state.ActiveVersionID
}

func normalizeDeliveryOutcome(outcome DeliveryOutcome) (string, string, error) {
	if outcome.Success {
		if strings.TrimSpace(outcome.Category) != "" || strings.TrimSpace(outcome.Reason) != "" {
			return "", "", fmt.Errorf("%w: successful delivery cannot have failure details", ErrInvalidOutcome)
		}
		return "", "", nil
	}
	category := strings.ToLower(strings.TrimSpace(outcome.Category))
	if !validErrorCategory(category, true) || category == ErrorCategoryUnknown {
		return "", "", fmt.Errorf("%w: delivery error category is invalid", ErrInvalidOutcome)
	}
	reason := strings.ToLower(strings.TrimSpace(outcome.Reason))
	if !validReason(reason) {
		return "", "", fmt.Errorf("%w: delivery reason must be a bounded machine-readable code", ErrInvalidOutcome)
	}
	return category, reason, nil
}

func normalizeProbeOutcome(outcome ProbeOutcome) (string, string, error) {
	if outcome.Success {
		if strings.TrimSpace(outcome.Category) != "" || strings.TrimSpace(outcome.Reason) != "" {
			return "", "", fmt.Errorf("%w: successful probe cannot have failure details", ErrInvalidOutcome)
		}
		return "", "", nil
	}
	category := strings.ToLower(strings.TrimSpace(outcome.Category))
	if !validErrorCategory(category, false) {
		return "", "", fmt.Errorf("%w: probe error category is invalid", ErrInvalidOutcome)
	}
	reason := strings.ToLower(strings.TrimSpace(outcome.Reason))
	if !validReason(reason) {
		return "", "", fmt.Errorf("%w: probe reason must be a bounded machine-readable code", ErrInvalidOutcome)
	}
	return category, reason, nil
}

func validReason(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func sourceTargetID(source EffectiveSource) string {
	if source.Mode == ModeActive && source.VersionID != nil {
		return source.VersionID.String()
	}
	return "environment-fallback"
}

func enqueueCircuitOpenedTx(
	ctx context.Context,
	tx pgx.Tx,
	source EffectiveSource,
	category, reason string,
	now time.Time,
) error {
	if err := audit.EnqueueTargetResultTx(
		ctx, tx, AuditCircuitOpened, nil, "system", "mail_runtime", sourceTargetID(source),
		"success", "medium", "", "",
		map[string]any{"error_category": category, "reason": reason}, now,
	); err != nil {
		return fmt.Errorf("auditing mail circuit open: %w", err)
	}
	return nil
}

func enqueueCircuitRecoveredTx(ctx context.Context, tx pgx.Tx, targetID, reason string, now time.Time) error {
	if err := audit.EnqueueTargetResultTx(
		ctx, tx, AuditCircuitRecovered, nil, "system", "mail_runtime", targetID,
		"success", "low", "", "", map[string]any{"reason": reason}, now,
	); err != nil {
		return fmt.Errorf("auditing mail circuit recovery: %w", err)
	}
	return nil
}
