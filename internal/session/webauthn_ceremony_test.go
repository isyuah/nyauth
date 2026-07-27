package session

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWebAuthnCeremonyIsOpaqueAndSingleUse(t *testing.T) {
	store, mini := testStore(t)
	data := &WebAuthnCeremonyData{
		SessionData: []byte("opaque-msgpack"), Purpose: "login", ReturnTo: "/dashboard",
	}
	const token = "raw-webauthn-ceremony-token"
	if err := store.SaveWebAuthnCeremony(t.Context(), token, data, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if data.CreatedAt.IsZero() || data.ExpiresAt.IsZero() {
		t.Fatalf("ceremony timestamps were not completed: %#v", data)
	}
	loaded, err := store.GetWebAuthnCeremony(t.Context(), token)
	if err != nil || loaded.Purpose != data.Purpose {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
	consumed, err := store.ConsumeWebAuthnCeremony(t.Context(), token)
	if err != nil || string(consumed.SessionData) != "opaque-msgpack" {
		t.Fatalf("consumed=%#v err=%v", consumed, err)
	}
	if _, err := store.ConsumeWebAuthnCeremony(t.Context(), token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume error=%v", err)
	}
	for _, key := range mini.Keys() {
		if strings.Contains(key, token) {
			t.Fatalf("raw ceremony token leaked into Redis key %q", key)
		}
	}
}

func TestWebAuthnAndMFAPendingAreConsumedAtomically(t *testing.T) {
	store, _ := testStore(t)
	ceremony := &WebAuthnCeremonyData{
		SessionData: []byte("session"), Purpose: "mfa", UserID: "user-1", ParentDigest: "parent",
	}
	pending := &MFAPendingData{
		UserID: "user-1", Username: "alice", Purpose: "login", PrimaryMethod: "password",
	}
	if err := store.SaveWebAuthnCeremony(t.Context(), "ceremony", ceremony, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveMFAPending(t.Context(), "pending", pending, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	mismatch := *ceremony
	mismatch.ParentDigest = "different"
	if err := store.ConsumeWebAuthnCeremonyAndMFAPending(
		t.Context(), "ceremony", &mismatch, "pending", pending,
	); !errors.Is(err, ErrValueMismatch) {
		t.Fatalf("mismatch error=%v", err)
	}
	if _, err := store.GetWebAuthnCeremony(t.Context(), "ceremony"); err != nil {
		t.Fatalf("mismatch consumed ceremony: %v", err)
	}
	if _, err := store.GetMFAPending(t.Context(), "pending"); err != nil {
		t.Fatalf("mismatch consumed MFA pending: %v", err)
	}
	if err := store.ConsumeWebAuthnCeremonyAndMFAPending(
		t.Context(), "ceremony", ceremony, "pending", pending,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetWebAuthnCeremony(t.Context(), "ceremony"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ceremony remained after atomic consume: %v", err)
	}
	if _, err := store.GetMFAPending(t.Context(), "pending"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("MFA pending remained after atomic consume: %v", err)
	}
}
