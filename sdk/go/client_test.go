package nyauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestComputeS256ChallengeRFC7636(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := computeS256Challenge(verifier); got != want {
		t.Fatalf("computeS256Challenge() = %q, want %q", got, want)
	}
}

func TestPublicClientIDIsEncodedInTokenRequestBody(t *testing.T) {
	var form url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		form = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "access", TokenType: "Bearer"})
	}))
	defer server.Close()

	client := NewClient(Config{Issuer: server.URL, ClientID: "public-client", RedirectURI: server.URL + "/callback"})
	if _, err := client.ExchangeCodePKCE(context.Background(), "code", "verifier"); err != nil {
		t.Fatalf("ExchangeCodePKCE: %v", err)
	}
	if got := form.Get("client_id"); got != "public-client" {
		t.Fatalf("client_id = %q, want public-client", got)
	}
}

func TestAuthorizationURLAlwaysUsesS256(t *testing.T) {
	client := NewClient(Config{Issuer: "https://auth.example", ClientID: "client", RedirectURI: "https://app.example/callback"})
	authURL, state, verifier, challenge, err := client.GetAuthorizationURL([]string{"openid"}, "fixed-state")
	if err != nil {
		t.Fatalf("GetAuthorizationURL: %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if state != "fixed-state" || verifier == "" || challenge == "" {
		t.Fatalf("unexpected PKCE result: state=%q verifier=%q challenge=%q", state, verifier, challenge)
	}
	if got := parsed.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", got)
	}
}
