package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var safeQueryParameters = map[string]struct{}{
	"client_id":             {},
	"code_challenge_method": {},
	"days":                  {},
	"event":                 {},
	"format":                {},
	"grant_type":            {},
	"limit":                 {},
	"page":                  {},
	"page_size":             {},
	"response_type":         {},
	"result":                {},
	"risk":                  {},
	"scope":                 {},
	"token_type_hint":       {},
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
			route := chi.RouteContext(r.Context()).RoutePattern()
			if route == "" {
				route = "unmatched"
			}
			level := slog.LevelInfo
			if status >= http.StatusInternalServerError {
				level = slog.LevelError
			} else if status >= http.StatusBadRequest {
				level = slog.LevelWarn
			}
			slog.LogAttrs(r.Context(), level, "http request completed",
				slog.String("request_id", middleware.GetReqID(r.Context())),
				slog.String("http.method", r.Method),
				slog.String("http.route", route),
				slog.String("http.target", redactedRequestURI(r.URL, route)),
				slog.Int("http.status_code", status),
				slog.Int("http.response_bytes", wrapped.BytesWritten()),
				slog.Int64("http.duration_ms", time.Since(started).Milliseconds()),
				slog.String("client.address", requestIP(r)),
				slog.String("error.class", httpErrorClass(status)),
			)
		}()
		next.ServeHTTP(wrapped, r)
	})
}

func structuredRecoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				slog.ErrorContext(r.Context(), "http handler panic recovered",
					"request_id", middleware.GetReqID(r.Context()),
					"panic_type", fmt.Sprintf("%T", recovered),
					"stack", string(debug.Stack()),
				)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func httpErrorClass(status int) string {
	switch {
	case status >= http.StatusInternalServerError:
		return "server_error"
	case status >= http.StatusBadRequest:
		return "client_error"
	default:
		return "none"
	}
}

func redactedRequestURI(target *url.URL, route string) string {
	path := strings.TrimSpace(route)
	if path == "" || path == "unmatched" {
		path = "/[unmatched]"
	}
	query := target.Query()
	for key := range query {
		if !isSafeQueryParameter(key) {
			query.Set(key, "[REDACTED]")
		}
	}
	if encoded := query.Encode(); encoded != "" {
		return path + "?" + encoded
	}
	return path
}

func isSafeQueryParameter(key string) bool {
	for safe := range safeQueryParameters {
		if strings.EqualFold(key, safe) {
			return true
		}
	}
	return false
}
