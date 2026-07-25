package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

func validatePKCE(verifier, challenge, method string) bool {
	if method != "S256" || !validPKCEVerifier(verifier) || !validPKCEChallenge(challenge) {
		return false
	}
	digest := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) == 1
}

func validPKCEChallenge(challenge string) bool {
	if len(challenge) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil
}

func validPKCEVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, char := range verifier {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '.' || char == '_' || char == '~' {
			continue
		}
		return false
	}
	return true
}
