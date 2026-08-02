package humanverification

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

type verifierStub struct {
	result VerifyResult
	err    error
	calls  int
}

func (v *verifierStub) Verify(_ context.Context, _ VerifyInput) (VerifyResult, error) {
	v.calls++
	return v.result, v.err
}

func TestManagerPublicChallengeUsesActivePolicyAndAvailability(t *testing.T) {
	version := &Version{
		ID: uuid.New(), Settings: Settings{
			Provider: ProviderTurnstile, SiteKey: "public-site-key", WidgetMode: WidgetManaged,
		},
	}
	manager := &Manager{}
	manager.snapshot.Store(&managerSnapshot{effective: EffectiveConfig{
		State: State{
			Mode: ModeActive, Revision: 7,
			Policy: Policy{Registration: true, LoginMode: LoginAdaptive, LoginTriggerAfter: 3},
		},
		Configured: true, Available: true, Version: version,
	}, verifier: &verifierStub{}})

	registration := manager.PublicChallenge(ActionRegistration, 0)
	if !registration.Enabled || !registration.Required || !registration.Available || registration.SiteKey != "public-site-key" {
		t.Fatalf("registration challenge = %#v", registration)
	}
	if login := manager.PublicChallenge(ActionLogin, 2); !login.Enabled || login.Required {
		t.Fatalf("login challenge before threshold = %#v", login)
	}
	if login := manager.PublicChallenge(ActionLogin, 3); !login.Required || !login.Available {
		t.Fatalf("login challenge at threshold = %#v", login)
	}
	if unsupported := manager.PublicChallenge(Action(255), 0); unsupported.Enabled || unsupported.Required || unsupported.SiteKey != "" {
		t.Fatalf("unsupported action exposed challenge = %#v", unsupported)
	}

	manager.snapshot.Store(&managerSnapshot{effective: EffectiveConfig{
		State:      State{Mode: ModeActive, Revision: 8, Policy: Policy{Registration: true, LoginMode: LoginOff, LoginTriggerAfter: 3}},
		Configured: true, Available: false, Version: version,
	}})
	unavailable := manager.PublicChallenge(ActionRegistration, 0)
	if !unavailable.Enabled || !unavailable.Required || unavailable.Available {
		t.Fatalf("unavailable challenge must fail closed = %#v", unavailable)
	}
}

func TestManagerVerifyOnlyCallsProviderWhenPolicyRequiresIt(t *testing.T) {
	stub := &verifierStub{result: VerifyResult{Hostname: "auth.example.test", Action: ActionLogin.String()}}
	manager := &Manager{}
	manager.snapshot.Store(&managerSnapshot{
		effective: EffectiveConfig{
			State:      State{Mode: ModeActive, Revision: 4, Policy: Policy{LoginMode: LoginAdaptive, LoginTriggerAfter: 3}},
			Configured: true, Available: true,
		},
		verifier: stub,
	})
	input := VerifyInput{Token: "token", Action: ActionLogin, IdempotencyKey: uuid.NewString()}
	if err := manager.Verify(context.Background(), input, 2); err != nil || stub.calls != 0 {
		t.Fatalf("verification below threshold called provider: calls=%d err=%v", stub.calls, err)
	}
	if err := manager.Verify(context.Background(), input, 3); err != nil || stub.calls != 1 {
		t.Fatalf("verification at threshold: calls=%d err=%v", stub.calls, err)
	}

	manager.snapshot.Store(&managerSnapshot{effective: EffectiveConfig{
		State:      State{Mode: ModeActive, Revision: 5, Policy: Policy{LoginMode: LoginAlways, LoginTriggerAfter: 3}},
		Configured: true, Available: false,
	}})
	if err := manager.Verify(context.Background(), input, 0); !errors.Is(err, ErrVerificationUnavailable) {
		t.Fatalf("unavailable provider error = %v", err)
	}
}

func TestManagerInstallRejectsStaleSnapshotsAndRecoversSameRevision(t *testing.T) {
	manager := &Manager{}
	if !manager.install(&managerSnapshot{effective: EffectiveConfig{State: State{Revision: 10}, Configured: true}}) {
		t.Fatal("initial runtime snapshot was rejected")
	}
	if manager.install(&managerSnapshot{effective: EffectiveConfig{State: State{Revision: 9}}}) {
		t.Fatal("stale runtime snapshot replaced the current revision")
	}
	if manager.install(&managerSnapshot{effective: EffectiveConfig{State: State{Revision: 10}, Configured: true}}) {
		t.Fatal("duplicate unavailable runtime revision replaced the current snapshot")
	}
	if !manager.install(&managerSnapshot{effective: EffectiveConfig{State: State{Revision: 10}, Configured: true, Available: true}}) {
		t.Fatal("same-revision recovery was rejected")
	}
	if manager.install(&managerSnapshot{effective: EffectiveConfig{State: State{Revision: 10}, Configured: true}}) {
		t.Fatal("same-revision failure replaced a healthy snapshot")
	}
	if snapshot := manager.Snapshot(); snapshot.State.Revision != 10 || !snapshot.Available {
		t.Fatalf("current snapshot = %#v", snapshot)
	}
}
