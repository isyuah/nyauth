package server

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

func (s *Server) userAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated, err := s.sessionMiddleware.GetSession(r)
		if err != nil {
			if !isNoSession(err) {
				s.sessionMiddleware.DestroySession(w, r)
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		userID, err := uuid.Parse(authenticated.Data.UserID)
		if err != nil {
			s.sessionMiddleware.DestroySession(w, r)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid session"})
			return
		}
		current, err := s.userService.GetByID(r.Context(), userID)
		if err != nil || current.Status != models.UserStatusActive || current.AuthVersion != authenticated.Data.AuthVersion {
			s.sessionMiddleware.DestroySession(w, r)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session expired"})
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
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin access required"})
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
		if authenticated == nil || provided == "" || len(provided) != len(authenticated.Data.CSRFToken) || subtle.ConstantTimeCompare([]byte(provided), []byte(authenticated.Data.CSRFToken)) != 1 {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid CSRF token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireCurrentPasswordChange(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := currentUserFromContext(r)
		if user != nil && user.MustChangePassword && r.URL.Path != "/api/me/password" && r.URL.Path != "/api/session" && r.URL.Path != "/api/logout" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "password change required"})
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

func (s *Server) resolveClientIP(r *http.Request) string {
	candidate := remoteIP(r.RemoteAddr)
	if candidate == nil {
		return ""
	}
	if !ipInNetworks(candidate, s.trustedProxies) {
		return candidate.String()
	}
	chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(chain) - 1; i >= 0; i-- {
		if !ipInNetworks(candidate, s.trustedProxies) {
			return candidate.String()
		}
		next := net.ParseIP(strings.TrimSpace(chain[i]))
		if next == nil {
			continue
		}
		candidate = next
	}
	if len(chain) == 1 && strings.TrimSpace(chain[0]) == "" {
		if real := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); real != nil {
			candidate = real
		}
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
