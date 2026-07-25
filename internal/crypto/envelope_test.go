package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestEnvelopeRoundTripAndContextBinding(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	envelope, err := EncryptEnvelope(key, "primary", "jwk-private-key", []byte("secret"), []byte("kid-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(envelope, "v1:primary:") {
		t.Fatalf("unexpected envelope: %q", envelope)
	}
	got, err := DecryptEnvelope(map[string][]byte{"primary": key}, "jwk-private-key", envelope, []byte("kid-1"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Fatalf("got %q", got)
	}
	if _, err := DecryptEnvelope(map[string][]byte{"primary": key}, "other-purpose", envelope, []byte("kid-1")); err == nil {
		t.Fatal("purpose substitution succeeded")
	}
	if _, err := DecryptEnvelope(map[string][]byte{"primary": key}, "jwk-private-key", envelope, []byte("kid-2")); err == nil {
		t.Fatal("AAD substitution succeeded")
	}
	if _, err := DecryptEnvelope(map[string][]byte{"other": key}, "jwk-private-key", envelope, []byte("kid-1")); !errors.Is(err, ErrUnknownEnvelopeKey) {
		t.Fatalf("got %v", err)
	}
}

func TestEnvelopeRejectsInvalidInputs(t *testing.T) {
	if _, err := EncryptEnvelope(make([]byte, 31), "primary", "purpose", nil, nil); err == nil {
		t.Fatal("accepted short key")
	}
	if _, err := EncryptEnvelope(make([]byte, 32), "bad:key", "purpose", nil, nil); err == nil {
		t.Fatal("accepted invalid key ID")
	}
	if _, err := DecryptEnvelope(map[string][]byte{}, "purpose", "not-an-envelope", nil); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("got %v", err)
	}
}
