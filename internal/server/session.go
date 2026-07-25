package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/pkg/models"
)

const sessionCookieName = "nyauth_session"
const sessionTTL = 24 * time.Hour

type SessionMiddleware struct {
	sessionStore *session.Store
	secureCookie bool
}

func NewSessionMiddleware(store *session.Store, secureCookie bool) *SessionMiddleware {
	return &SessionMiddleware{sessionStore: store, secureCookie: secureCookie}
}

type AuthenticatedSession struct {
	ID   string
	Data *session.SessionData
}

func (m *SessionMiddleware) CreateSession(w http.ResponseWriter, r *http.Request, user *models.User) (*AuthenticatedSession, error) {
	sessionID, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, err
	}
	data := &session.SessionData{UserID: user.ID.String(), Username: user.Username, AuthVersion: user.AuthVersion}
	if err := m.sessionStore.SaveSession(r.Context(), sessionID, data, sessionTTL); err != nil {
		return nil, err
	}
	m.setCookie(w, sessionID, int(sessionTTL.Seconds()))
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

func (m *SessionMiddleware) DestroySession(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		_ = m.sessionStore.DeleteSession(r.Context(), cookie.Value)
	}
	m.clearCookie(w)
}

func (m *SessionMiddleware) GetSession(r *http.Request) (*AuthenticatedSession, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, err
	}
	data, err := m.sessionStore.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return nil, err
	}
	return &AuthenticatedSession{ID: cookie.Value, Data: data}, nil
}

func (m *SessionMiddleware) setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: value, Path: "/", HttpOnly: true, Secure: m.secureCookie, SameSite: http.SameSiteLaxMode, MaxAge: maxAge, Expires: time.Now().Add(time.Duration(maxAge) * time.Second)})
}
func (m *SessionMiddleware) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true, Secure: m.secureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
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
func isNoSession(err error) bool {
	return errors.Is(err, http.ErrNoCookie) || errors.Is(err, session.ErrNotFound)
}
