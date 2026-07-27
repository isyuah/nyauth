package provider

import "testing"

func TestNormalizeAvatarPolicyUsesNonNilEmptyListForBuiltInProviders(t *testing.T) {
	hosts, err := NormalizeAvatarPolicy("github", false, nil)
	if err != nil {
		t.Fatalf("NormalizeAvatarPolicy() error = %v", err)
	}
	if hosts == nil || len(hosts) != 0 {
		t.Fatalf("normalized hosts = %#v, want non-nil empty list", hosts)
	}
}
