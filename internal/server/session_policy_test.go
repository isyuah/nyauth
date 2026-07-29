package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestSessionPolicyAppliesRuntimeLifecycleChanges(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	ctx := context.Background()

	setLifecycle := func(t *testing.T, absoluteTTL, recentTTL string) int64 {
		t.Helper()
		value := settings.Lifecycle{
			SessionAbsoluteTTL:      absoluteTTL,
			RecentAuthenticationTTL: recentTTL,
			AuditRetentionDays:      365,
		}
		revision, err := testApp.app.settingsMgr.SetLifecycle(
			ctx,
			value,
			testApp.app.settingsMgr.LifecycleSnapshot().Revision,
			"session-policy-test",
			"",
			audit.MutationAudit{
				Event: models.AuditSettingsUpdated, ActorID: uuid.New(),
				ActorName: "session-policy-test", Result: "success", RiskLevel: "high",
			},
		)
		if err != nil {
			t.Fatalf("set lifecycle policy: %v", err)
		}
		return revision
	}

	flushSessions := func(t *testing.T) {
		t.Helper()
		if err := testApp.app.rdb.FlushDB(ctx).Err(); err != nil {
			t.Fatalf("flush session Redis database: %v", err)
		}
	}

	requestSession := func(sessionID string) (*httptest.ResponseRecorder, *AuthenticatedSession, error) {
		request := httptest.NewRequest(http.MethodGet, "/api/session", nil)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
		response := httptest.NewRecorder()
		authenticated, err := testApp.app.sessionMiddleware.GetSession(response, request)
		return response, authenticated, err
	}

	t.Run("shortening invalidates an over-age session", func(t *testing.T) {
		flushSessions(t)
		oldRevision := setLifecycle(t, "48h", "10m")
		now := time.Now().UTC().Truncate(time.Millisecond)
		data := &session.SessionData{
			UserID: "shortened-user", Username: "shortened", AuthVersion: 1, SessionVersion: 1,
			CreatedAt: now.Add(-25 * time.Hour), LastSeenAt: now, AuthenticatedAt: now,
			PolicyRevision: oldRevision,
		}
		if err := testApp.app.sessionStore.SaveSession(ctx, "shortened-session", data, 23*time.Hour); err != nil {
			t.Fatalf("save session under old lifecycle: %v", err)
		}
		setLifecycle(t, "24h", "10m")

		response, authenticated, err := requestSession("shortened-session")
		if !errors.Is(err, session.ErrNotFound) || authenticated != nil {
			t.Fatalf("shortened session = %#v, err=%v; want expired", authenticated, err)
		}
		if !strings.Contains(response.Header().Get("Set-Cookie"), "Max-Age=0") {
			t.Fatalf("expired session cookie was not cleared: %q", response.Header().Get("Set-Cookie"))
		}
		if _, err := testApp.app.sessionStore.GetSession(ctx, "shortened-session"); !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("shortened session remained in Redis: %v", err)
		}
	})

	t.Run("extension refreshes a still-active session", func(t *testing.T) {
		flushSessions(t)
		oldRevision := setLifecycle(t, "1h", "10m")
		now := time.Now().UTC().Truncate(time.Millisecond)
		createdAt := now.Add(-30 * time.Minute)
		data := &session.SessionData{
			UserID: "extended-user", Username: "extended", AuthVersion: 1, SessionVersion: 1,
			CreatedAt: createdAt, LastSeenAt: now, AuthenticatedAt: now,
			PolicyRevision: oldRevision,
		}
		if err := testApp.app.sessionStore.SaveSession(ctx, "extended-session", data, 30*time.Minute); err != nil {
			t.Fatalf("save session under old lifecycle: %v", err)
		}
		newRevision := setLifecycle(t, "2h", "10m")

		response, authenticated, err := requestSession("extended-session")
		if err != nil {
			t.Fatalf("load active session after extension: %v", err)
		}
		wantExpiresAt := createdAt.Add(2 * time.Hour)
		if authenticated.Data.PolicyRevision != newRevision || !authenticated.Data.SessionExpiresAt.Equal(wantExpiresAt) {
			t.Fatalf("extended session revision=%d expires=%s, want revision=%d expires=%s",
				authenticated.Data.PolicyRevision, authenticated.Data.SessionExpiresAt, newRevision, wantExpiresAt)
		}
		cookies := response.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != sessionCookieName || cookies[0].MaxAge < 89*60 || cookies[0].MaxAge > 91*60 {
			t.Fatalf("extended session cookie = %#v", cookies)
		}
		persisted, err := testApp.app.sessionStore.GetSession(ctx, "extended-session")
		if err != nil {
			t.Fatalf("load persisted extended session: %v", err)
		}
		if persisted.PolicyRevision != newRevision {
			t.Fatalf("persisted policy revision = %d, want %d", persisted.PolicyRevision, newRevision)
		}
	})

	t.Run("extension does not restore an expired Redis session", func(t *testing.T) {
		flushSessions(t)
		oldRevision := setLifecycle(t, "1h", "10m")
		now := time.Now().UTC().Truncate(time.Millisecond)
		data := &session.SessionData{
			UserID: "expired-user", Username: "expired", AuthVersion: 1, SessionVersion: 1,
			CreatedAt: now.Add(-30 * time.Minute), LastSeenAt: now, AuthenticatedAt: now,
			PolicyRevision: oldRevision,
		}
		if err := testApp.app.sessionStore.SaveSession(ctx, "expired-session", data, 30*time.Minute); err != nil {
			t.Fatalf("save session under old lifecycle: %v", err)
		}
		testApp.mini.FastForward(31 * time.Minute)
		setLifecycle(t, "2h", "10m")

		response, authenticated, err := requestSession("expired-session")
		if !errors.Is(err, session.ErrNotFound) || authenticated != nil {
			t.Fatalf("expired session = %#v, err=%v; want not found", authenticated, err)
		}
		if response.Header().Get("Set-Cookie") != "" {
			t.Fatalf("missing Redis session was unexpectedly reissued: %q", response.Header().Get("Set-Cookie"))
		}
	})

	t.Run("recent authentication deadline follows the current lifecycle", func(t *testing.T) {
		flushSessions(t)
		oldRevision := setLifecycle(t, "2h", "2m")
		now := time.Now().UTC().Truncate(time.Millisecond)
		authenticatedAt := now.Add(-90 * time.Second)
		data := &session.SessionData{
			UserID: "recent-auth-user", Username: "recent-auth", AuthVersion: 1, SessionVersion: 1,
			CreatedAt: now.Add(-10 * time.Minute), LastSeenAt: now, AuthenticatedAt: authenticatedAt,
			PolicyRevision: oldRevision,
		}
		if err := testApp.app.sessionStore.SaveSession(ctx, "recent-auth-session", data, 110*time.Minute); err != nil {
			t.Fatalf("save recent-auth session: %v", err)
		}

		_, before, err := requestSession("recent-auth-session")
		if err != nil {
			t.Fatalf("load session before recent-auth change: %v", err)
		}
		if want := authenticatedAt.Add(2 * time.Minute); !before.Data.RecentAuthenticationExpiresAt.Equal(want) {
			t.Fatalf("recent-auth deadline before change = %s, want %s", before.Data.RecentAuthenticationExpiresAt, want)
		}
		if !isRecentAuthentication(before.Data.AuthenticatedAt, now, testApp.app.settingsMgr.Lifecycle().RecentAuthenticationDuration()) {
			t.Fatal("authentication should be recent under the two-minute policy")
		}

		setLifecycle(t, "2h", "1m")
		_, after, err := requestSession("recent-auth-session")
		if err != nil {
			t.Fatalf("load session after recent-auth change: %v", err)
		}
		if want := authenticatedAt.Add(time.Minute); !after.Data.RecentAuthenticationExpiresAt.Equal(want) {
			t.Fatalf("recent-auth deadline after change = %s, want %s", after.Data.RecentAuthenticationExpiresAt, want)
		}
		if isRecentAuthentication(after.Data.AuthenticatedAt, now, testApp.app.settingsMgr.Lifecycle().RecentAuthenticationDuration()) {
			t.Fatal("authentication remained recent after shortening the policy")
		}
	})
}
