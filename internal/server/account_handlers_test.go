package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

type fakeAccountActionService struct {
	requestPasswordResetErr error
	confirmPasswordResetErr error
	confirmPasswordUser     *models.User
}

func (f *fakeAccountActionService) RequestPasswordReset(context.Context, string, account.RequestMetadata) error {
	return f.requestPasswordResetErr
}

func (f *fakeAccountActionService) ConfirmPasswordReset(context.Context, string, string) (*models.User, error) {
	return f.confirmPasswordUser, f.confirmPasswordResetErr
}

func (f *fakeAccountActionService) RequestEmailVerification(context.Context, uuid.UUID, account.RequestMetadata) error {
	return nil
}

func (f *fakeAccountActionService) ConfirmEmailVerification(context.Context, string) (*models.User, error) {
	return nil, nil
}

func (f *fakeAccountActionService) RequestEmailChange(context.Context, uuid.UUID, string, time.Time, account.RequestMetadata) error {
	return nil
}

func (f *fakeAccountActionService) ConfirmEmailChange(context.Context, string) (*models.User, error) {
	return nil, nil
}

func newAccountHandlerTestServer(t *testing.T, service accountActionService) (*Server, *miniredis.Miniredis) {
	t.Helper()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	store := session.NewStore(rdb)
	return &Server{
		cfg:               &config.Config{Auth: config.AuthConfig{Issuer: "https://auth.example.test"}},
		accountService:    service,
		accountLimiter:    NewAccountActionLimiter(rdb),
		sessionStore:      store,
		sessionMiddleware: NewSessionMiddleware(store, true),
	}, mini
}

func TestPasswordResetRequestKeepsQueueFailureEnumerationSafe(t *testing.T) {
	t.Parallel()
	server, _ := newAccountHandlerTestServer(t, &fakeAccountActionService{requestPasswordResetErr: errors.New("database unavailable")})
	request := httptest.NewRequest(http.MethodPost, "/api/password/forgot", bytes.NewBufferString(`{"email":"known@example.test"}`))
	request.RemoteAddr = "192.0.2.10:12345"
	recorder := httptest.NewRecorder()

	server.handleRequestPasswordReset(recorder, request)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusAccepted, recorder.Body.String())
	}
	if body := strings.TrimSpace(recorder.Body.String()); body != `{"status":"accepted"}` {
		t.Fatalf("body = %s", body)
	}
}

func TestPasswordResetConfirmationRevokesBrowserSessions(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	service := &fakeAccountActionService{confirmPasswordUser: &models.User{ID: userID, AuthVersion: 2}}
	server, _ := newAccountHandlerTestServer(t, service)
	const sessionID = "existing-browser-session"
	if err := server.sessionStore.SaveSession(context.Background(), sessionID, &session.SessionData{UserID: userID.String(), AuthVersion: 1}, time.Hour); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/password/reset", bytes.NewBufferString(`{"token":"a-valid-token-with-at-least-thirty-two-bytes","new_password":"a sufficiently long replacement"}`))
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	recorder := httptest.NewRecorder()

	server.handleConfirmPasswordReset(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if _, err := server.sessionStore.GetSession(context.Background(), sessionID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("session lookup error = %v, want ErrNotFound", err)
	}
	setCookie := recorder.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, sessionCookieName+"=") || !strings.Contains(setCookie, "Max-Age=0") {
		t.Fatalf("session clear cookie missing: %q", setCookie)
	}
}

func TestAccountActionLimiterUsesHashedKeysAndEnforcesSubjectLimit(t *testing.T) {
	t.Parallel()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	limiter := NewAccountActionLimiter(rdb)
	ctx := context.Background()
	for attempt := 0; attempt < 5; attempt++ {
		allowed, _, err := limiter.Reserve(ctx, "password-reset", "192.0.2.20", "private@example.test")
		if err != nil || !allowed {
			t.Fatalf("attempt %d: allowed=%v err=%v", attempt+1, allowed, err)
		}
	}
	allowed, retry, err := limiter.Reserve(ctx, "password-reset", "192.0.2.20", "private@example.test")
	if err != nil {
		t.Fatalf("limited Reserve: %v", err)
	}
	if allowed || retry <= 0 {
		t.Fatalf("limited result allowed=%v retry=%v", allowed, retry)
	}
	for _, key := range mini.Keys() {
		if strings.Contains(key, "private@example.test") || strings.Contains(key, "192.0.2.20") {
			t.Fatalf("rate-limit key exposes private input: %q", key)
		}
	}
}
