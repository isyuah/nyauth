package mailruntime

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/nyasharp/nyauth/internal/account"
)

func TestManagerConcurrentLoadCannotRegressSnapshotRevision(t *testing.T) {
	firstLoadEntered := make(chan struct{})
	releaseFirstLoad := make(chan struct{})
	var loaderMu sync.Mutex
	loaderCalls := 0
	activeLoads := 0
	maxActiveLoads := 0

	var callbackMu sync.Mutex
	callbackRevisions := make([]int64, 0, 1)
	manager := &Manager{
		store: &Store{},
		loadEffectiveConfig: func(context.Context, *SMTPConfig) (EffectiveConfig, error) {
			loaderMu.Lock()
			loaderCalls++
			call := loaderCalls
			activeLoads++
			if activeLoads > maxActiveLoads {
				maxActiveLoads = activeLoads
			}
			loaderMu.Unlock()

			if call == 1 {
				close(firstLoadEntered)
				<-releaseFirstLoad
			}

			loaderMu.Lock()
			activeLoads--
			loaderMu.Unlock()
			if call == 1 {
				return EffectiveConfig{
					Mode: ModeDisabled, StateRevision: 2, CircuitState: CircuitClosed,
				}, nil
			}
			return EffectiveConfig{
				Mode: ModeDisabled, StateRevision: 1, CircuitState: CircuitClosed,
			}, nil
		},
		onSnapshot: func(effective EffectiveConfig) {
			callbackMu.Lock()
			callbackRevisions = append(callbackRevisions, effective.StateRevision)
			callbackMu.Unlock()
		},
	}

	firstResult := make(chan error, 1)
	go func() {
		firstResult <- manager.Load(context.Background())
	}()
	<-firstLoadEntered

	if manager.loadMu.TryLock() {
		manager.loadMu.Unlock()
		close(releaseFirstLoad)
		<-firstResult
		t.Fatal("Load released loadMu before effective configuration resolution completed")
	}

	secondStarted := make(chan struct{})
	secondResult := make(chan error, 1)
	go func() {
		close(secondStarted)
		secondResult <- manager.Load(context.Background())
	}()
	<-secondStarted
	close(releaseFirstLoad)

	if err := <-firstResult; err != nil {
		t.Fatalf("first Load returned error: %v", err)
	}
	if err := <-secondResult; err != nil {
		t.Fatalf("second Load returned error: %v", err)
	}

	loaderMu.Lock()
	gotLoaderCalls := loaderCalls
	gotMaxActiveLoads := maxActiveLoads
	loaderMu.Unlock()
	if gotLoaderCalls != 2 {
		t.Fatalf("loader calls = %d, want 2", gotLoaderCalls)
	}
	if gotMaxActiveLoads != 1 {
		t.Fatalf("concurrent effective configuration loads = %d, want 1", gotMaxActiveLoads)
	}

	snapshot := manager.snapshot.Load()
	if snapshot == nil {
		t.Fatal("snapshot was not installed")
	}
	if got := snapshot.effective.StateRevision; got != 2 {
		t.Fatalf("installed StateRevision = %d, want 2", got)
	}

	callbackMu.Lock()
	gotCallbackRevisions := append([]int64(nil), callbackRevisions...)
	callbackMu.Unlock()
	if len(gotCallbackRevisions) != 1 || gotCallbackRevisions[0] != 2 {
		t.Fatalf("snapshot callback revisions = %v, want [2]", gotCallbackRevisions)
	}
}

func TestManagerInstallTreatsEqualRevisionAsIdempotent(t *testing.T) {
	callbackCount := 0
	manager := &Manager{
		onSnapshot: func(EffectiveConfig) {
			callbackCount++
		},
	}
	installed := &managerSnapshot{effective: EffectiveConfig{
		Mode: ModeActive, StateRevision: 7, CircuitState: CircuitClosed,
	}}
	if !manager.install(installed) {
		t.Fatal("initial snapshot was not installed")
	}

	equalRevision := &managerSnapshot{effective: EffectiveConfig{
		Mode: ModeDisabled, StateRevision: 7, CircuitState: CircuitClosed,
	}}
	if manager.install(equalRevision) {
		t.Fatal("equal revision unexpectedly replaced the installed snapshot")
	}
	if got := manager.snapshot.Load(); got != installed {
		t.Fatal("equal revision changed the installed snapshot")
	}
	if callbackCount != 1 {
		t.Fatalf("snapshot callback count = %d, want 1", callbackCount)
	}
}

func TestRuntimeFailureDetailsOnlyTreatsPermanentConfigurationFailuresAsImmediateCircuitErrors(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantCategory string
		wantReason   string
	}{
		{
			name: "temporary authentication response",
			err: &account.SMTPError{
				Category: account.SMTPErrorAuthentication, Permanent: false, Err: errors.New("temporary authentication failure"),
			},
			wantCategory: ErrorCategoryTransport, wantReason: "smtp_transport_failed",
		},
		{
			name: "permanent authentication response",
			err: &account.SMTPError{
				Category: account.SMTPErrorAuthentication, Permanent: true, Err: errors.New("credentials rejected"),
			},
			wantCategory: ErrorCategoryAuthentication, wantReason: "smtp_authentication_failed",
		},
		{
			name: "temporary TLS response",
			err: &account.SMTPError{
				Category: account.SMTPErrorTLS, Permanent: false, Err: errors.New("TLS temporarily unavailable"),
			},
			wantCategory: ErrorCategoryTransport, wantReason: "smtp_transport_failed",
		},
		{
			name: "permanent configuration response",
			err: &account.SMTPError{
				Category: account.SMTPErrorConfiguration, Permanent: true, Err: errors.New("sender rejected"),
			},
			wantCategory: ErrorCategoryConfiguration, wantReason: "smtp_configuration_failed",
		},
		{
			name: "recipient response",
			err: &account.SMTPError{
				Category: account.SMTPErrorRecipient, Permanent: true, Err: errors.New("recipient rejected"),
			},
			wantCategory: ErrorCategoryRecipient, wantReason: "smtp_recipient_failed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			category, reason := runtimeFailureDetails(test.err)
			if category != test.wantCategory || reason != test.wantReason {
				t.Fatalf("category=%q reason=%q", category, reason)
			}
		})
	}
}
