package server

import (
	"net/url"
	"strings"
	"testing"
)

func TestRedactedRequestURI(t *testing.T) {
	t.Parallel()
	target, err := url.Parse("/end_session?client_id=public&id_token_hint=secret.jwt&CODE=authorization-code&state=csrf-state")
	if err != nil {
		t.Fatal(err)
	}
	got := redactedRequestURI(target)
	for _, secret := range []string{"secret.jwt", "authorization-code", "csrf-state"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted URI leaked %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "client_id=public") {
		t.Fatalf("non-sensitive query was removed: %s", got)
	}
	if count := strings.Count(got, "%5BREDACTED%5D"); count != 3 {
		t.Fatalf("redacted value count = %d, URI = %s", count, got)
	}
	if target.Query().Get("id_token_hint") != "secret.jwt" {
		t.Fatal("redaction mutated the request URL")
	}
}
