package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nyasharp/nyauth/pkg/models"
)

func TestBuildClientInitializesSecretMetadata(t *testing.T) {
	t.Parallel()
	rotatedAt := time.Date(2026, 7, 26, 8, 30, 0, 0, time.UTC)
	service := &Service{
		generateSecret: func() (string, error) { return "confidential-secret-value", nil },
		clock:          func() time.Time { return rotatedAt },
	}

	confidential, secret, err := service.buildClient(models.CreateClientRequest{
		Name: "Confidential", RedirectURIs: []string{"https://client.example/callback"},
		Grants: []string{models.GrantAuthorizationCode},
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret != "confidential-secret-value" || confidential.SecretHash == nil {
		t.Fatal("confidential client secret was not generated and hashed")
	}
	if confidential.SecretVersion != 1 || confidential.SecretRotatedAt == nil || !confidential.SecretRotatedAt.Equal(rotatedAt) {
		t.Fatalf("unexpected confidential secret metadata: version=%d rotated_at=%v", confidential.SecretVersion, confidential.SecretRotatedAt)
	}
	if confidential.SecretHint == nil || *confidential.SecretHint != "-value" {
		t.Fatalf("secret hint = %v, want %q", confidential.SecretHint, "-value")
	}

	public, secret, err := service.buildClient(models.CreateClientRequest{
		Name: "Public", RedirectURIs: []string{"https://client.example/callback"},
		Grants: []string{models.GrantAuthorizationCode}, IsPublic: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" || public.SecretHash != nil || public.SecretHint != nil || public.SecretVersion != 0 || public.SecretRotatedAt != nil {
		t.Fatalf("public client unexpectedly has secret metadata: %#v", public)
	}
}

func TestNormalizeOwnerID(t *testing.T) {
	t.Parallel()
	canonical := "2f1c9f8d-8fb2-4741-8a7c-3e9ce813e2ee"
	nonCanonical := "  {2F1C9F8D-8FB2-4741-8A7C-3E9CE813E2EE}  "
	normalized, err := normalizeOwnerID(&nonCanonical)
	if err != nil {
		t.Fatal(err)
	}
	if normalized == nil || *normalized != canonical {
		t.Fatalf("normalized owner = %v, want %q", normalized, canonical)
	}
	if normalized, err := normalizeOwnerID(nil); err != nil || normalized != nil {
		t.Fatalf("nil owner normalized to %v with error %v", normalized, err)
	}
	for _, value := range []string{"", "   ", "not-a-uuid"} {
		value := value
		if _, err := normalizeOwnerID(&value); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("normalizeOwnerID(%q) error = %v", value, err)
		}
	}
}

func TestUnauditedCreateRejectsOwnerAssignment(t *testing.T) {
	t.Parallel()
	ownerID := "2f1c9f8d-8fb2-4741-8a7c-3e9ce813e2ee"
	service := &Service{}
	if _, err := service.Create(context.Background(), models.CreateClientRequest{OwnerID: &ownerID}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("Create owner assignment error = %v", err)
	}
}
