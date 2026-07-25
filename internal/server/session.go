package server

import (
	"context"
	"net/http"
	"time"

	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/session"
)

const sessionCookieName = "nyauth_session"
const sessionTTL = 24 * time.Hour

// SessionMiddleware provides cookie-based session management.
type SessionMiddleware struct {
	sessionStore *session.Store
}

// NewSessionMiddleware creates a new session middleware.
func NewSessionMiddleware(store *session.Store) *SessionMiddleware {
	return &SessionMiddleware{sessionStore: store}
}

// CreateSession creates a new session and sets the cookie.
func (m *SessionMiddleware) CreateSession(w http.ResponseWriter, r *http.Request, userID, username string) error {
	sessionID, err := crypto.GenerateRandomString(32)
	if err != nil {
		return err
	}

	data := &session.SessionData{
		UserID:   userID,
		Username: username,
	}

	if err := m.sessionStore.SaveSession(r.Context(), sessionID, data, sessionTTL); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})

	return nil
}

// DestroySession removes the session and clears the cookie.
func (m *SessionMiddleware) DestroySession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		_ = m.sessionStore.DeleteSession(r.Context(), cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// GetSessionData returns session data from the cookie, or nil if not logged in.
func (m *SessionMiddleware) GetSessionData(r *http.Request) *session.SessionData {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}

	data, err := m.sessionStore.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return nil
	}

	return data
}

// context key for session data
type contextKey string

const sessionContextKey contextKey = "session"

// WithSessionData stores session data in context.
func WithSessionData(ctx context.Context, data *session.SessionData) context.Context {
	return context.WithValue(ctx, sessionContextKey, data)
}

// SessionFromContext retrieves session data from context.
func SessionFromContext(ctx context.Context) *session.SessionData {
	if v, ok := ctx.Value(sessionContextKey).(*session.SessionData); ok {
		return v
	}
	return nil
}
