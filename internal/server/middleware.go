package server

import (
	"net/http"

	"github.com/google/uuid"
)

// adminAuthMiddleware validates Bearer tokens and checks for admin role.
func (s *Server) adminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing authorization"})
			return
		}

		claims, err := s.tokenService.ValidateAccessToken(r.Context(), token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}

		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid token subject"})
			return
		}

		user, err := s.userService.GetByID(r.Context(), userID)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
			return
		}

		if user.Role != "admin" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin access required"})
			return
		}

		next.ServeHTTP(w, r)
	})
}
