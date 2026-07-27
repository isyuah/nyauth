package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMFAPendingIsSingleUseAndExcludedFromActiveSessions(t *testing.T) {
	store, mini := testStore(t)
	ctx := context.Background()
	data := &MFAPendingData{
		UserID: "user-1", Username: "alice", AuthVersion: 3, SessionVersion: 2,
		Purpose: "login", PrimaryMethod: "password", ReturnTo: "/dashboard",
	}
	const token = "raw-mfa-pending-token"
	if err := store.SaveMFAPending(ctx, token, data, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if data.CSRFToken == "" || data.ExpiresAt.IsZero() {
		t.Fatalf("pending metadata was not completed: %#v", data)
	}
	if count, err := store.CountActiveSessions(ctx); err != nil || count != 0 {
		t.Fatalf("active sessions count=%d err=%v", count, err)
	}
	if sessions, err := store.ListUserSessions(ctx, data.UserID); err != nil || len(sessions) != 0 {
		t.Fatalf("user sessions=%v err=%v", sessions, err)
	}
	loaded, err := store.GetMFAPending(ctx, token)
	if err != nil || loaded.UserID != data.UserID {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
	consumed, err := store.ConsumeMFAPending(ctx, token)
	if err != nil || consumed.CSRFToken != data.CSRFToken {
		t.Fatalf("consumed=%#v err=%v", consumed, err)
	}
	if _, err := store.ConsumeMFAPending(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume error=%v", err)
	}
	for _, key := range mini.Keys() {
		if strings.Contains(key, token) {
			t.Fatalf("raw pending token leaked into Redis key %q", key)
		}
	}
}
