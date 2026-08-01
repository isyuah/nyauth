package trusteddevice

import (
	"errors"
	"strings"
	"testing"
)

func TestTrustedDeviceTokenRoundTripAndRejectsMalformedValues(t *testing.T) {
	token, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseToken(token.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != token {
		t.Fatalf("parsed token = %#v, want %#v", parsed, token)
	}
	if strings.Contains(token.Secret, "+") || strings.Contains(token.Secret, "/") || strings.Contains(token.Secret, "=") {
		t.Fatalf("secret is not unpadded URL-safe base64: %q", token.Secret)
	}

	for _, value := range []string{"", token.ID.String(), token.ID.String() + ".short", "not-a-uuid." + token.Secret, token.String() + ".extra"} {
		if _, err := ParseToken(value); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("ParseToken(%q) error = %v, want ErrInvalidToken", value, err)
		}
	}
}
