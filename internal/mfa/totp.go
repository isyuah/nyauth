package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	totpPeriodSeconds = int64(30)
	totpDigits        = 6
	totpWindow        = int64(1)
	totpSecretBytes   = 20
)

var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

func generateTOTPSecret() ([]byte, string, error) {
	secret := make([]byte, totpSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", fmt.Errorf("generating TOTP secret: %w", err)
	}
	return secret, base32NoPadding.EncodeToString(secret), nil
}

func totpURI(issuer, account, encodedSecret string) (string, error) {
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)
	if issuer == "" || account == "" || encodedSecret == "" {
		return "", fmt.Errorf("issuer, account, and secret are required")
	}
	query := url.Values{
		"secret":    []string{encodedSecret},
		"issuer":    []string{issuer},
		"algorithm": []string{"SHA1"},
		"digits":    []string{strconv.Itoa(totpDigits)},
		"period":    []string{strconv.FormatInt(totpPeriodSeconds, 10)},
	}
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + query.Encode(), nil
}

func matchTOTP(secret []byte, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	for _, value := range code {
		if value < '0' || value > '9' {
			return 0, false
		}
	}
	current := now.UTC().Unix() / totpPeriodSeconds
	var matched int64
	found := false
	for offset := -totpWindow; offset <= totpWindow; offset++ {
		step := current + offset
		if step < 0 {
			continue
		}
		expected := totpCode(secret, uint64(step))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 && (!found || step > matched) {
			matched = step
			found = true
		}
	}
	return matched, found
}

func totpCode(secret []byte, step uint64) string {
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, step)
	digest := hmac.New(sha1.New, secret)
	_, _ = digest.Write(message)
	sum := digest.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%0*d", totpDigits, value%1_000_000)
}
