package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeProviderEndpointClassifiesReachabilityWithoutCredentials(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("diagnostic probe sent credentials")
		}
		switch r.URL.Path {
		case "/token":
			w.WriteHeader(http.StatusMethodNotAllowed)
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"one"}]}`))
		case "/failure":
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer server.Close()
	if check := probeProviderEndpoint(context.Background(), server.Client(), "token_endpoint", server.URL+"/token", false); check.Status != "passed" {
		t.Fatalf("token check = %#v", check)
	}
	if check := probeProviderEndpoint(context.Background(), server.Client(), "jwks_endpoint", server.URL+"/jwks", true); check.Status != "passed" {
		t.Fatalf("JWKS check = %#v", check)
	}
	if check := probeProviderEndpoint(context.Background(), server.Client(), "token_endpoint", server.URL+"/failure", false); check.Status != "failed" {
		t.Fatalf("failure check = %#v", check)
	}
}

func TestProbeProviderEndpointRejectsMalformedJWKS(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()
	if check := probeProviderEndpoint(context.Background(), server.Client(), "jwks_endpoint", server.URL, true); check.Status != "failed" {
		t.Fatalf("malformed JWKS check = %#v", check)
	}
}
