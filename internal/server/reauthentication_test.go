package server

import (
	"context"
	"net/http"
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

func TestRecentAuthenticationMiddlewareRejectsStaleSessions(t *testing.T) {
	t.Parallel()
	server := &Server{}
	called := false
	handler := server.recentAuthenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	staleRequest := httptest.NewRequest(http.MethodPost, "/api/admin/clients/client-1/publisher-verification", nil)
	staleRequest = staleRequest.WithContext(withAuthenticatedSession(staleRequest.Context(), &AuthenticatedSession{
		Data: &session.SessionData{AuthenticatedAt: time.Now().UTC().Add(-account.DefaultReauthenticationTTL - time.Minute)},
	}))
	staleResponse := httptest.NewRecorder()
	handler.ServeHTTP(staleResponse, staleRequest)
	if staleResponse.Code != http.StatusForbidden || called {
		t.Fatalf("stale response=%d called=%v body=%s", staleResponse.Code, called, staleResponse.Body.String())
	}

	freshRequest := httptest.NewRequest(http.MethodPost, "/api/admin/clients/client-1/publisher-verification", nil)
	freshRequest = freshRequest.WithContext(withAuthenticatedSession(freshRequest.Context(), &AuthenticatedSession{
		Data: &session.SessionData{AuthenticatedAt: time.Now().UTC()},
	}))
	freshResponse := httptest.NewRecorder()
	handler.ServeHTTP(freshResponse, freshRequest)
	if freshResponse.Code != http.StatusNoContent || !called {
		t.Fatalf("fresh response=%d called=%v body=%s", freshResponse.Code, called, freshResponse.Body.String())
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

	marked, err := middleware.MarkReauthenticated(httptest.NewRecorder(), request, updated)
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
