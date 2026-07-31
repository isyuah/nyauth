package humanverification

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTurnstileVerifierValidatesHostnameActionAndRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.Form.Get("secret") != "secret" || r.Form.Get("response") != "token" || r.Form.Get("remoteip") != "203.0.113.5" || r.Form.Get("idempotency_key") != "d7d45cc1-8c8f-431c-9f75-834c1bd2b4a7" {
			t.Fatalf("unexpected form: %#v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"hostname":"auth.example.test","action":"register","error-codes":[]}`))
	}))
	defer server.Close()
	verifier, err := NewTurnstileVerifier(TurnstileOptions{Secret: "secret", ExpectedHostname: "auth.example.test", Endpoint: server.URL})
	if err != nil {
		t.Fatalf("NewTurnstileVerifier: %v", err)
	}
	_, err = verifier.Verify(context.Background(), VerifyInput{
		Token: "token", RemoteIP: "203.0.113.5", Action: ActionRegistration,
		IdempotencyKey: "d7d45cc1-8c8f-431c-9f75-834c1bd2b4a7",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestTurnstileVerifierClassifiesFailures(t *testing.T) {
	tests := []struct {
		name string
		body string
		want error
	}{
		{"rejected", `{"success":false,"error-codes":["invalid-input-response"]}`, ErrVerificationRejected},
		{"configuration", `{"success":false,"error-codes":["invalid-input-secret"]}`, ErrVerificationUnavailable},
		{"wrong action", `{"success":true,"hostname":"auth.example.test","action":"login","error-codes":[]}`, ErrVerificationRejected},
		{"wrong hostname", `{"success":true,"hostname":"other.example.test","action":"register","error-codes":[]}`, ErrVerificationRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(test.body)) }))
			defer server.Close()
			verifier, err := NewTurnstileVerifier(TurnstileOptions{Secret: "secret", ExpectedHostname: "auth.example.test", Endpoint: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifier.Verify(context.Background(), VerifyInput{Token: "token", Action: ActionRegistration, IdempotencyKey: "d7d45cc1-8c8f-431c-9f75-834c1bd2b4a7"})
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify error = %v, want %v", err, test.want)
			}
		})
	}
}
