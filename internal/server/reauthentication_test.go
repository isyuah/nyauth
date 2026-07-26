package server

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

func TestRecentAuthenticationWindow(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	for _, test := range []struct {
		name  string
		value time.Time
		want  bool
	}{
		{name: "fresh", value: now.Add(-time.Minute), want: true},
		{name: "boundary", value: now.Add(-account.DefaultReauthenticationTTL), want: true},
		{name: "expired", value: now.Add(-account.DefaultReauthenticationTTL - time.Nanosecond), want: false},
		{name: "future", value: now.Add(2 * time.Minute), want: false},
		{name: "missing", value: time.Time{}, want: false},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := isRecentAuthentication(test.value, now); got != test.want {
				t.Fatalf("isRecentAuthentication() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestMarkReauthenticatedPreservesSessionIdentity(t *testing.T) {
	t.Parallel()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	store := session.NewStore(rdb)
	middleware := NewSessionMiddleware(store, false)
	userID := uuid.New()
	data := &session.SessionData{UserID: userID.String(), Username: "before", AuthVersion: 4, AuthenticatedAt: time.Now().Add(-time.Hour)}
	if err := store.SaveSession(context.Background(), "session-id", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/api/me/reauth/password", nil)
	request = request.WithContext(withAuthenticatedSession(request.Context(), &AuthenticatedSession{ID: "session-id", Data: data}))
	updated := &models.User{ID: userID, Username: "after", AuthVersion: 4}

	marked, err := middleware.MarkReauthenticated(request, updated)
	if err != nil {
		t.Fatalf("MarkReauthenticated error = %v", err)
	}
	if marked.Data.PublicID != data.PublicID || marked.Data.Username != "after" || !isRecentAuthentication(marked.Data.AuthenticatedAt, time.Now().UTC()) {
		t.Fatalf("unexpected marked session: %#v", marked.Data)
	}
	persisted, err := store.GetSession(context.Background(), "session-id")
	if err != nil {
		t.Fatal(err)
	}
	if persisted.PublicID != data.PublicID || persisted.Username != "after" {
		t.Fatalf("unexpected persisted session: %#v", persisted)
	}
}
