package authorization

import (
	"slices"
	"testing"
)

func TestCanonicalScopesSortsAndDeduplicates(t *testing.T) {
	got := canonicalScopes([]string{" profile ", "openid", "", "profile", "email"})
	want := []string{"email", "openid", "profile"}
	if !slices.Equal(got, want) {
		t.Fatalf("canonical scopes = %v, want %v", got, want)
	}
}
