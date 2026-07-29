package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

const sessionCookieName = "nyauth_session"
const mfaPendingCookieName = "nyauth_mfa_pending"
const sessionTTL = 24 * time.Hour
const mfaPendingTTL = 5 * time.Minute

type SessionMiddleware struct {
	sessionStore *session.Store
	secureCookie bool
	settings     *settings.Manager
}

func NewSessionMiddleware(store *session.Store, secureCookie bool, managers ...*settings.Manager) *SessionMiddleware {
	var manager *settings.Manager
	if len(managers) > 0 {
		manager = managers[0]
	}
	return &SessionMiddleware{sessionStore: store, secureCookie: secureCookie, settings: manager}
}

type AuthenticatedSession struct {
	ID   string
	Data *session.SessionData
}

type MFAPendingSession struct {
	Token string
	Data  *session.MFAPendingData
}

func (m *SessionMiddleware) CreateSession(w http.ResponseWriter, r *http.Request, user *models.User) (*AuthenticatedSession, error) {
	sessionID, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	policy := m.lifecycleSnapshot()
	data := &session.SessionData{
		UserID: user.ID.String(), Username: user.Username, AuthVersion: user.AuthVersion, SessionVersion: user.SessionVersion,
		IPAddress: requestIP(r), UserAgent: truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength),
		CreatedAt: now, LastSeenAt: now, AuthenticatedAt: now, PolicyRevision: policy.Revision,
	}
	m.applyDeadlines(data, policy.Value)
	expiresAt := effectiveSessionExpiry(data)
	if _, err := m.sessionStore.SaveSessionWithLimit(
		r.Context(), sessionID, data, expiresAt.Sub(now), policy.Value.MaxConcurrentSessions,
	); err != nil {
		return nil, err
	}
	m.setCookieUntil(w, sessionID, expiresAt, now)
	return &AuthenticatedSession{ID: sessionID, Data: data}, nil
}

func (m *SessionMiddleware) RotateSession(w http.ResponseWriter, r *http.Request, user *models.User) (*AuthenticatedSession, error) {
	created, err := m.CreateSession(w, r, user)
	if err != nil {
		return nil, err
	}
	if _, err := m.sessionStore.DeleteOtherUserSessions(r.Context(), user.ID.String(), created.ID); err != nil {
		_ = m.sessionStore.DeleteSession(r.Context(), created.ID)
		m.clearCookie(w)
		return nil, err
	}
	return created, nil
}

func (m *SessionMiddleware) MarkReauthenticated(w http.ResponseWriter, r *http.Request, user *models.User) (*AuthenticatedSession, error) {
	authenticated := sessionFromContext(r.Context())
	if authenticated == nil || authenticated.Data == nil {
		return nil, errors.New("authenticated session is unavailable")
	}
	expectedAuthVersion := authenticated.Data.AuthVersion
	expectedSessionVersion := authenticated.Data.SessionVersion
	now := time.Now().UTC()
	policy := m.lifecycleSnapshot()
	updatedData := *authenticated.Data
	updatedData.AuthenticatedAt = now
	updatedData.LastSeenAt = now
	updatedData.Username = user.Username
	updatedData.AuthVersion = user.AuthVersion
	updatedData.SessionVersion = user.SessionVersion
	updatedData.PolicyRevision = policy.Revision
	m.applyDeadlines(&updatedData, policy.Value)
	expiresAt := effectiveSessionExpiry(&updatedData)
	remaining := expiresAt.Sub(now)
	if remaining <= 0 {
		_ = m.sessionStore.DeleteSession(r.Context(), authenticated.ID)
		return nil, session.ErrNotFound
	}
	if err := m.sessionStore.UpdateSession(
		r.Context(), authenticated.ID, &updatedData,
		expectedAuthVersion, expectedSessionVersion, remaining,
	); err != nil {
		return nil, err
	}
	authenticated.Data = &updatedData
	m.setCookieUntil(w, authenticated.ID, expiresAt, now)
	return authenticated, nil
}

func (m *SessionMiddleware) DestroySession(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		_ = m.sessionStore.DeleteSession(r.Context(), cookie.Value)
	}
	m.clearCookie(w)
}

func (m *SessionMiddleware) GetSession(w http.ResponseWriter, r *http.Request) (*AuthenticatedSession, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, err
	}
	data, err := m.sessionStore.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	policy := m.lifecycleSnapshot()
	m.applyDeadlines(data, policy.Value)
	expiresAt := effectiveSessionExpiry(data)
	remaining := expiresAt.Sub(now)
	if remaining <= 0 {
		_ = m.sessionStore.DeleteSession(r.Context(), cookie.Value)
		m.clearCookie(w)
		return nil, session.ErrNotFound
	}
	shouldTouch := data.LastSeenAt.IsZero() || now.Sub(data.LastSeenAt) >= sessionTouchInterval(policy.Value)
	if data.PolicyRevision != policy.Revision {
		expectedAuthVersion, expectedSessionVersion := data.AuthVersion, data.SessionVersion
		data.PolicyRevision = policy.Revision
		if shouldTouch {
			data.LastSeenAt = now
			m.applyDeadlines(data, policy.Value)
			expiresAt = effectiveSessionExpiry(data)
			remaining = expiresAt.Sub(now)
		}
		if err := m.sessionStore.UpdateSession(
			r.Context(), cookie.Value, data, expectedAuthVersion, expectedSessionVersion, remaining,
		); err != nil {
			return nil, err
		}
		m.setCookieUntil(w, cookie.Value, expiresAt, now)
	} else if shouldTouch {
		expectedAuthVersion, expectedSessionVersion := data.AuthVersion, data.SessionVersion
		data.LastSeenAt = now
		m.applyDeadlines(data, policy.Value)
		expiresAt = effectiveSessionExpiry(data)
		remaining = expiresAt.Sub(now)
		if err := m.sessionStore.UpdateSession(
			r.Context(), cookie.Value, data, expectedAuthVersion, expectedSessionVersion, remaining,
		); err != nil {
			return nil, err
		}
		m.setCookieUntil(w, cookie.Value, expiresAt, now)
	}
	return &AuthenticatedSession{ID: cookie.Value, Data: data}, nil
}

func (m *SessionMiddleware) CreateMFAPending(w http.ResponseWriter, r *http.Request, data *session.MFAPendingData) (*MFAPendingSession, error) {
	if existing, err := r.Cookie(mfaPendingCookieName); err == nil {
		_ = m.sessionStore.DeleteMFAPending(r.Context(), existing.Value)
	}
	token, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, err
	}
	if err := m.sessionStore.SaveMFAPending(r.Context(), token, data, mfaPendingTTL); err != nil {
		return nil, err
	}
	m.setNamedCookie(w, mfaPendingCookieName, token, int(mfaPendingTTL.Seconds()))
	return &MFAPendingSession{Token: token, Data: data}, nil
}

func (m *SessionMiddleware) GetMFAPending(r *http.Request) (*MFAPendingSession, error) {
	cookie, err := r.Cookie(mfaPendingCookieName)
	if err != nil {
		return nil, err
	}
	data, err := m.sessionStore.GetMFAPending(r.Context(), cookie.Value)
	if err != nil {
		return nil, err
	}
	return &MFAPendingSession{Token: cookie.Value, Data: data}, nil
}

func (m *SessionMiddleware) ConsumeMFAPending(w http.ResponseWriter, r *http.Request) (*MFAPendingSession, error) {
	cookie, err := r.Cookie(mfaPendingCookieName)
	if err != nil {
		return nil, err
	}
	data, err := m.sessionStore.ConsumeMFAPending(r.Context(), cookie.Value)
	if err != nil {
		return nil, err
	}
	m.clearNamedCookie(w, mfaPendingCookieName)
	return &MFAPendingSession{Token: cookie.Value, Data: data}, nil
}

func (m *SessionMiddleware) DestroyMFAPending(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(mfaPendingCookieName); err == nil {
		_ = m.sessionStore.DeleteMFAPending(r.Context(), cookie.Value)
	}
	m.clearNamedCookie(w, mfaPendingCookieName)
}

func (m *SessionMiddleware) setCookie(w http.ResponseWriter, value string, maxAge int) {
	m.setNamedCookie(w, sessionCookieName, value, maxAge)
}

func (m *SessionMiddleware) setCookieUntil(w http.ResponseWriter, value string, expiresAt, now time.Time) {
	maxAge := int((expiresAt.Sub(now) + time.Second - 1) / time.Second)
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: value, Path: "/", HttpOnly: true,
		Secure: m.secureCookie, SameSite: http.SameSiteLaxMode,
		MaxAge: maxAge, Expires: expiresAt,
	})
}
func (m *SessionMiddleware) clearCookie(w http.ResponseWriter) {
	m.clearNamedCookie(w, sessionCookieName)
}
func (m *SessionMiddleware) setNamedCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: m.secureCookie, SameSite: http.SameSiteLaxMode, MaxAge: maxAge, Expires: time.Now().Add(time.Duration(maxAge) * time.Second)})
}
func (m *SessionMiddleware) clearNamedCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: m.secureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}

func (m *SessionMiddleware) lifecycleSnapshot() settings.Versioned[settings.Lifecycle] {
	if m.settings == nil {
		return settings.Versioned[settings.Lifecycle]{Value: settings.DefaultLifecycle(365)}
	}
	return m.settings.LifecycleSnapshot()
}

func (m *SessionMiddleware) applyDeadlines(data *session.SessionData, lifecycle settings.Lifecycle) {
	data.SessionExpiresAt = data.CreatedAt.Add(lifecycle.SessionAbsoluteDuration())
	data.SessionIdleExpiresAt = data.LastSeenAt.Add(lifecycle.SessionIdleDuration())
	data.RecentAuthenticationExpiresAt = data.AuthenticatedAt.Add(lifecycle.RecentAuthenticationDuration())
}

func effectiveSessionExpiry(data *session.SessionData) time.Time {
	if data.SessionIdleExpiresAt.Before(data.SessionExpiresAt) {
		return data.SessionIdleExpiresAt
	}
	return data.SessionExpiresAt
}

func sessionTouchInterval(lifecycle settings.Lifecycle) time.Duration {
	interval := lifecycle.SessionIdleDuration() / 2
	if interval > 5*time.Minute {
		return 5 * time.Minute
	}
	if interval < time.Second {
		return time.Second
	}
	return interval
}

type contextKey string

const (
	sessionContextKey     contextKey = "session"
	currentUserContextKey contextKey = "current-user"
	clientIPContextKey    contextKey = "client-ip"
)

func withAuthenticatedSession(ctx context.Context, value *AuthenticatedSession) context.Context {
	return context.WithValue(ctx, sessionContextKey, value)
}
func sessionFromContext(ctx context.Context) *AuthenticatedSession {
	value, _ := ctx.Value(sessionContextKey).(*AuthenticatedSession)
	return value
}
func currentUserFromContext(r *http.Request) *models.User {
	value, _ := r.Context().Value(currentUserContextKey).(*models.User)
	return value
}
