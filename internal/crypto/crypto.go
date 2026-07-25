package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const DummyPasswordHash = "$argon2id$v=19$m=65536,t=1,p=4$c3RhdGljLWR1bW15LXNhbHQ$Yv7sTUTZhgAhq7/Oc3b1T3sBv8vH5k/pQEE0A4E1fTk"

var argon2Slots = make(chan struct{}, 4)

// SetArgon2Concurrency configures the process-wide Argon2 work limit. Call it
// once during startup before serving requests.
func SetArgon2Concurrency(limit int) {
	if limit < 1 {
		limit = 4
	}
	argon2Slots = make(chan struct{}, limit)
}

func withArgon2Slot(fn func()) {
	argon2Slots <- struct{}{}
	defer func() { <-argon2Slots }()
	fn()
}

// HashPassword hashes a password using argon2id.
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	var hash []byte
	withArgon2Slot(func() {
		hash = argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	})

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		64*1024,
		1,
		4,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return encoded, nil
}

// VerifyPassword verifies a password against an argon2id hash.
func VerifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	// Expected: ["", "argon2id", "v=19", "m=65536,t=1,p=4", "salt", "hash"]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("invalid hash format")
	}

	// Parse version
	version, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil {
		return false, fmt.Errorf("parsing version: %w", err)
	}
	if version != argon2.Version {
		return false, fmt.Errorf("unsupported argon2 version")
	}

	// Parse m, t, p
	params := parts[3]
	var memory uint32
	var timeCost uint32
	var parallelism uint8

	for _, p := range strings.Split(params, ",") {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return false, fmt.Errorf("invalid argon2 parameters")
		}
		switch kv[0] {
		case "m":
			v, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return false, fmt.Errorf("invalid argon2 memory")
			}
			memory = uint32(v)
		case "t":
			v, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return false, fmt.Errorf("invalid argon2 time")
			}
			timeCost = uint32(v)
		case "p":
			v, err := strconv.ParseUint(kv[1], 10, 8)
			if err != nil {
				return false, fmt.Errorf("invalid argon2 parallelism")
			}
			parallelism = uint8(v)
		default:
			return false, fmt.Errorf("unknown argon2 parameter")
		}
	}
	if memory < 8*1024 || memory > 1024*1024 || timeCost < 1 || timeCost > 10 || parallelism < 1 || parallelism > 16 {
		return false, fmt.Errorf("argon2 parameters out of range")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decoding salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decoding hash: %w", err)
	}
	if len(salt) < 8 || len(salt) > 64 || len(hash) < 16 || len(hash) > 64 {
		return false, fmt.Errorf("argon2 salt or hash length out of range")
	}

	var comparisonHash []byte
	withArgon2Slot(func() {
		comparisonHash = argon2.IDKey([]byte(password), salt, timeCost, memory, parallelism, uint32(len(hash)))
	})

	return subtle.ConstantTimeCompare(hash, comparisonHash) == 1, nil
}

// HashClientSecret hashes a high-entropy client secret with SHA-256.
func HashClientSecret(secret string) string {
	digest := sha256.Sum256([]byte(secret))
	return "$sha256$" + base64.RawStdEncoding.EncodeToString(digest[:])
}

// VerifyClientSecret compares a client secret with a SHA-256 digest.
func VerifyClientSecret(secret, encodedHash string) bool {
	if !strings.HasPrefix(encodedHash, "$sha256$") {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(encodedHash, "$sha256$"))
	if err != nil || len(expected) != sha256.Size {
		return false
	}
	actual := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(expected, actual[:]) == 1
}

// Encrypt encrypts plaintext using AES-256-GCM with the given key.
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with the given key.
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

// GenerateRandomString generates a cryptographically random string.
func GenerateRandomString(byteLength int) (string, error) {
	b := make([]byte, byteLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateClientID generates a random client ID.
func GenerateClientID() (string, error) {
	return GenerateRandomString(16)
}

// GenerateClientSecret generates a random client secret.
func GenerateClientSecret() (string, error) {
	return GenerateRandomString(32)
}

// ComputeS256Challenge computes PKCE S256 challenge from verifier.
func ComputeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
