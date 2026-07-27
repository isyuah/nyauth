package mfa

import (
	"testing"
	"time"
)

func TestTOTPUsesRFC6238SHA1VectorsTruncatedToSixDigits(t *testing.T) {
	t.Parallel()
	secret := []byte("12345678901234567890")
	tests := []struct {
		unix int64
		want string
	}{
		{unix: 59, want: "287082"},
		{unix: 1111111109, want: "081804"},
		{unix: 1111111111, want: "050471"},
		{unix: 1234567890, want: "005924"},
		{unix: 2000000000, want: "279037"},
		{unix: 20000000000, want: "353130"},
	}
	for _, test := range tests {
		step := uint64(test.unix / totpPeriodSeconds)
		if got := totpCode(secret, step); got != test.want {
			t.Fatalf("TOTP at %d = %q, want %q", test.unix, got, test.want)
		}
	}
}

func TestMatchTOTPAcceptsOnlySixDigitsWithinOneStep(t *testing.T) {
	t.Parallel()
	secret := []byte("12345678901234567890")
	now := time.Unix(1_700_000_000, 0).UTC()
	current := now.Unix() / totpPeriodSeconds
	for _, step := range []int64{current - 1, current, current + 1} {
		code := totpCode(secret, uint64(step))
		matched, ok := matchTOTP(secret, code, now)
		if !ok || matched != step {
			t.Fatalf("step %d: matched=%d ok=%v", step, matched, ok)
		}
	}
	for _, code := range []string{"", "12345", "1234567", "abcdef", totpCode(secret, uint64(current+2))} {
		if _, ok := matchTOTP(secret, code, now); ok {
			t.Fatalf("unexpectedly accepted %q", code)
		}
	}
}
