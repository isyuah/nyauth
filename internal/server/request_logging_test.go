package server

import (
	"net/url"
	"strings"
	"testing"
)

func TestRedactedRequestURI(t *testing.T) {
	t.Parallel()
	target, err := url.Parse("/api/admin/users/private-user-id?client_id=public&id_token_hint=secret.jwt&CODE=authorization-code&state=csrf-state&nonce=oidc-nonce&challenge=consent-secret&csrf_token=header-copy&return_to=%2Fauthorize%3Fstate%3Dnested-state&actor=alice&target=private-client&ip=192.0.2.1&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback%3Fsecret%3Dvalue&unknown=sensitive-value")
	if err != nil {
		t.Fatal(err)
	}
	got := redactedRequestURI(target, "/api/admin/users/{id}")
	for _, secret := range []string{"private-user-id", "secret.jwt", "authorization-code", "csrf-state", "oidc-nonce", "consent-secret", "header-copy", "nested-state", "alice", "private-client", "192.0.2.1", "client.example", "sensitive-value"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted URI leaked %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "client_id=public") {
		t.Fatalf("non-sensitive query was removed: %s", got)
	}
	if !strings.HasPrefix(got, "/api/admin/users/{id}?") {
		t.Fatalf("request target did not use the route pattern: %s", got)
	}
	if count := strings.Count(got, "%5BREDACTED%5D"); count != 12 {
		t.Fatalf("redacted value count = %d, URI = %s", count, got)
	}
	if target.Query().Get("id_token_hint") != "secret.jwt" {
		t.Fatal("redaction mutated the request URL")
	}
}

func TestRedactedRequestURIHidesUnmatchedPaths(t *testing.T) {
	t.Parallel()
	target, err := url.Parse("/forgotten-secret-path?format=cef")
	if err != nil {
		t.Fatal(err)
	}
	if got := redactedRequestURI(target, "unmatched"); got != "/[unmatched]?format=cef" {
		t.Fatalf("unmatched request target = %q", got)
	}
}

func TestRedactedRequestURIHidesDeviceUserCode(t *testing.T) {
	t.Parallel()
	target, err := url.Parse("/device?user_code=ABCD-EFGH")
	if err != nil {
		t.Fatal(err)
	}
	got := redactedRequestURI(target, "/device")
	if strings.Contains(got, "ABCD") || !strings.Contains(got, "%5BREDACTED%5D") {
		t.Fatalf("device user code was not redacted: %s", got)
	}
}
