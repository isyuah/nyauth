package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// base64URLEncode encodes bytes to base64url without padding.
func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// sha256Sum returns the SHA-256 hash of a string.
func sha256Sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}
