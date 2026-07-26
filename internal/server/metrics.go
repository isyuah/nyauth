package server

import (
	"net"
	"net/http"
)

func (s *Server) requireInternalMetricsClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := net.ParseIP(requestIP(r))
		if ip == nil || !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
