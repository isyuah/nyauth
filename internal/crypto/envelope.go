package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const envelopeVersion = "v1"

var (
	ErrInvalidEnvelope    = errors.New("invalid encrypted envelope")
	ErrUnknownEnvelopeKey = errors.New("unknown envelope key")
)

func EncryptEnvelope(masterKey []byte, keyID, purpose string, plaintext, aad []byte) (string, error) {
	if len(masterKey) != 32 {
		return "", fmt.Errorf("master key must be exactly 32 bytes, got %d", len(masterKey))
	}
	if !validEnvelopeLabel(keyID) {
		return "", fmt.Errorf("invalid envelope key ID")
	}
	if purpose == "" {
		return "", fmt.Errorf("envelope purpose is required")
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", fmt.Errorf("creating envelope cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating envelope GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generating envelope nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, envelopeAAD(keyID, purpose, aad))
	return strings.Join([]string{envelopeVersion, keyID, base64.RawURLEncoding.EncodeToString(sealed)}, ":"), nil
}

func DecryptEnvelope(masterKeys map[string][]byte, purpose, envelope string, aad []byte) ([]byte, error) {
	version, keyID, payload, err := ParseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	if version != envelopeVersion {
		return nil, fmt.Errorf("%w: unsupported version %q", ErrInvalidEnvelope, version)
	}
	masterKey, ok := masterKeys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownEnvelopeKey, keyID)
	}
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key %q must be exactly 32 bytes, got %d", keyID, len(masterKey))
	}
	if purpose == "" {
		return nil, fmt.Errorf("envelope purpose is required")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding payload: %v", ErrInvalidEnvelope, err)
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("creating envelope cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating envelope GCM: %w", err)
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, fmt.Errorf("%w: ciphertext is too short", ErrInvalidEnvelope)
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, envelopeAAD(keyID, purpose, aad))
	if err != nil {
		return nil, fmt.Errorf("decrypting envelope: %w", err)
	}
	return plaintext, nil
}

func ParseEnvelope(envelope string) (version, keyID, payload string, err error) {
	parts := strings.Split(envelope, ":")
	if len(parts) != 3 || parts[0] == "" || !validEnvelopeLabel(parts[1]) || parts[2] == "" {
		return "", "", "", ErrInvalidEnvelope
	}
	return parts[0], parts[1], parts[2], nil
}

func validEnvelopeLabel(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func envelopeAAD(keyID, purpose string, aad []byte) []byte {
	prefix := []byte(envelopeVersion + "\x00" + keyID + "\x00" + purpose + "\x00")
	return append(prefix, aad...)
}
