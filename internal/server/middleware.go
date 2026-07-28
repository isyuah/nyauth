package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

func (s *Server) userAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated, err := s.sessionMiddleware.GetSession(r)
		switch {
		case errors.Is(err, http.ErrNoCookie):
			writeAPIError(w, http.StatusUnauthorized, "authentication required")
			return
		case errors.Is(err, session.ErrNotFound):
			s.sessionMiddleware.DestroySession(w, r)
			writeAPIError(w, http.StatusUnauthorized, "session expired")
			return
		case err != nil:
			writeAPIError(w, http.StatusServiceUnavailable, "session service unavailable")
			return
		}
		userID, err := uuid.Parse(authenticated.Data.UserID)
		if err != nil {
			s.sessionMiddleware.DestroySession(w, r)
			writeAPIError(w, http.StatusUnauthorized, "invalid session")
			return
		}
		current, err := s.userService.GetByID(r.Context(), userID)
		if err != nil {
			if user.IsNotFound(err) {
				s.sessionMiddleware.DestroySession(w, r)
				writeAPIError(w, http.StatusUnauthorized, "session expired")
				return
			}
			writeAPIError(w, http.StatusServiceUnavailable, "account service unavailable")
			return
		}
		if current.Status != models.UserStatusActive ||
			current.AuthVersion != authenticated.Data.AuthVersion ||
			current.SessionVersion != authenticated.Data.SessionVersion {
			s.sessionMiddleware.DestroySession(w, r)
			writeAPIError(w, http.StatusUnauthorized, "session expired")
			return
		}
		ctx := context.WithValue(r.Context(), currentUserContextKey, current)
		ctx = withAuthenticatedSession(ctx, authenticated)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) adminAuthMiddleware(next http.Handler) http.Handler {
	return s.userAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := currentUserFromContext(r)
		if user == nil || user.Role != "admin" {
			writeAPIError(w, http.StatusForbidden, "admin access required")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		authenticated := sessionFromContext(r.Context())
		provided := r.Header.Get("X-CSRF-Token")
		rejectionReason := ""
		switch {
		case authenticated == nil:
			rejectionReason = "missing_session"
		case provided == "":
			rejectionReason = "missing_token"
		case len(provided) != len(authenticated.Data.CSRFToken) || subtle.ConstantTimeCompare([]byte(provided), []byte(authenticated.Data.CSRFToken)) != 1:
			rejectionReason = "mismatch"
		}
		if rejectionReason != "" {
			s.telemetry.RecordCSRFReject(r.Context(), rejectionReason)
			writeAPIError(w, http.StatusForbidden, "invalid CSRF token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireCurrentPasswordChange(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := currentUserFromContext(r)
		if user != nil && user.MustChangePassword && r.URL.Path != "/api/me/password" && r.URL.Path != "/api/session" && r.URL.Path != "/api/logout" {
			writeAPIError(w, http.StatusForbidden, "password change required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func parseTrustedProxyCIDRs(values []string) []*net.IPNet {
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(strings.TrimSpace(value))
		if err == nil {
			result = append(result, network)
		}
	}
	return result
}
func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
func remoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}

func forwardedIP(value string) net.IP {
	value = strings.TrimSpace(value)
	if parsed := net.ParseIP(value); parsed != nil {
		return parsed
	}
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return nil
	}
	return net.ParseIP(strings.TrimSpace(host))
}

func (s *Server) resolveClientIP(r *http.Request) string {
	peer := remoteIP(r.RemoteAddr)
	if peer == nil {
		return ""
	}
	candidate := peer
	if !ipInNetworks(candidate, s.trustedProxies) {
		return candidate.String()
	}
	forwardedFor := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if forwardedFor == "" {
		if real := forwardedIP(r.Header.Get("X-Real-IP")); real != nil {
			candidate = real
		}
		return candidate.String()
	}
	chain := strings.Split(forwardedFor, ",")
	for i := len(chain) - 1; i >= 0; i-- {
		if !ipInNetworks(candidate, s.trustedProxies) {
			return candidate.String()
		}
		next := forwardedIP(chain[i])
		if next == nil {
			return peer.String()
		}
		candidate = next
	}
	return candidate.String()
}

func (s *Server) clientIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.resolveClientIP(r)
		ctx := context.WithValue(r.Context(), clientIPContextKey, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		next.ServeHTTP(w, r)
	})
}
func requestIP(r *http.Request) string {
	value, _ := r.Context().Value(clientIPContextKey).(string)
	if value != "" {
		return value
	}
	ip := remoteIP(r.RemoteAddr)
	if ip != nil {
		return ip.String()
	}
	return ""
}

func (s *Server) validSameOriginRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	issuer, err := url.Parse(s.cfg.Auth.Issuer)
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Scheme, issuer.Scheme) && strings.EqualFold(parsed.Host, issuer.Host)
}
