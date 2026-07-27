package mfa

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"

	nyacrypto "github.com/nyasharp/nyauth/internal/crypto"
)

const (
	recoveryCodeCount        = 10
	recoverySelectorBytes    = 5
	recoverySecretBytes      = 10
	recoverySelectorLength   = 8
	recoveryNormalizedLength = 24
)

type recoveryCodeRecord struct {
	selectorHash []byte
	codeHash     string
}

func generateRecoveryCodes() ([]string, []recoveryCodeRecord, error) {
	codes := make([]string, 0, recoveryCodeCount)
	records := make([]recoveryCodeRecord, 0, recoveryCodeCount)
	for range recoveryCodeCount {
		selector := make([]byte, recoverySelectorBytes)
		secret := make([]byte, recoverySecretBytes)
		if _, err := rand.Read(selector); err != nil {
			return nil, nil, fmt.Errorf("generating recovery code selector: %w", err)
		}
		if _, err := rand.Read(secret); err != nil {
			return nil, nil, fmt.Errorf("generating recovery code secret: %w", err)
		}
		selectorText := base32NoPadding.EncodeToString(selector)
		secretText := base32NoPadding.EncodeToString(secret)
		normalized := selectorText + secretText
		hash, err := nyacrypto.HashPassword(normalized)
		if err != nil {
			return nil, nil, fmt.Errorf("hashing recovery code: %w", err)
		}
		digest := sha256.Sum256([]byte(selectorText))
		codes = append(codes, selectorText+"-"+secretText)
		records = append(records, recoveryCodeRecord{selectorHash: digest[:], codeHash: hash})
	}
	return codes, records, nil
}

func parseRecoveryCode(code string) (normalized string, selectorHash []byte, ok bool) {
	normalized = strings.ToUpper(strings.TrimSpace(code))
	normalized = strings.NewReplacer("-", "", " ", "").Replace(normalized)
	if len(normalized) != recoveryNormalizedLength {
		return "", nil, false
	}
	for _, value := range normalized {
		if (value < 'A' || value > 'Z') && (value < '2' || value > '7') {
			return "", nil, false
		}
	}
	selector := normalized[:recoverySelectorLength]
	digest := sha256.Sum256([]byte(selector))
	return normalized, digest[:], true
}
