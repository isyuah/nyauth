package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/nyasharp/nyauth/internal/config"
)

func TestIssuanceMiddlewareOnlyWrapsIssuanceEndpoints(t *testing.T) {
	handler := &Handler{config: &config.Config{}}
	handler.SetIssuanceMiddleware(func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		})
	})
	wantControlled := map[string]bool{
		http.MethodGet + " /authorize":             true,
		http.MethodPost + " /device_authorization": true,
		http.MethodPost + " /token":                true,
	}
	wantRoutes := map[string]bool{
		http.MethodGet + " /.well-known/openid-configuration": true,
		http.MethodGet + " /.well-known/jwks.json":            true,
		http.MethodGet + " /authorize":                        true,
		http.MethodPost + " /device_authorization":            true,
		http.MethodPost + " /token":                           true,
		http.MethodPost + " /revoke":                          true,
		http.MethodPost + " /introspect":                      true,
		http.MethodGet + " /userinfo":                         true,
		http.MethodPost + " /userinfo":                        true,
		http.MethodGet + " /end_session":                      true,
	}

	seen := make(map[string]bool, len(wantRoutes))
	err := chi.Walk(handler.Routes(), func(method, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		key := method + " " + route
		seen[key] = true
		sentinel := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		for index := len(middlewares) - 1; index >= 0; index-- {
			sentinel = middlewares[index](sentinel)
		}
		recorder := httptest.NewRecorder()
		sentinel.ServeHTTP(recorder, httptest.NewRequest(method, route, nil))
		controlled := recorder.Code == http.StatusTeapot
		if controlled != wantControlled[key] {
			t.Errorf("%s controlled=%v, want %v", key, controlled, wantControlled[key])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for route := range wantRoutes {
		if !seen[route] {
			t.Errorf("route %s was not registered", route)
		}
	}
}
