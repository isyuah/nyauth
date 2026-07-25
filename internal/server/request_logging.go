package server

import (
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

var sensitiveQueryParameters = map[string]struct{}{
	"access_token":  {},
	"client_secret": {},
	"code":          {},
	"code_verifier": {},
	"id_token_hint": {},
	"password":      {},
	"refresh_token": {},
	"state":         {},
	"token":         {},
}

func redactedRequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		defer func() {
			status := wrapped.Status()
			if status == 0 {
				status = http.StatusOK
			}
			log.Printf("[%s] %q from %s - %d %dB in %s",
				middleware.GetReqID(r.Context()),
				r.Method+" "+redactedRequestURI(r.URL)+" "+r.Proto,
				r.RemoteAddr,
				status,
				wrapped.BytesWritten(),
				time.Since(started),
			)
		}()
		next.ServeHTTP(wrapped, r)
	})
}

func redactedRequestURI(target *url.URL) string {
	path := target.EscapedPath()
	if path == "" {
		path = "/"
	}
	query := target.Query()
	for key := range query {
		if isSensitiveQueryParameter(key) {
			query.Set(key, "[REDACTED]")
		}
	}
	if encoded := query.Encode(); encoded != "" {
		return path + "?" + encoded
	}
	return path
}

func isSensitiveQueryParameter(key string) bool {
	for sensitive := range sensitiveQueryParameters {
		if strings.EqualFold(key, sensitive) {
			return true
		}
	}
	return false
}
