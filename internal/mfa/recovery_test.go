package mfa

import (
	"encoding/hex"
	"strings"
	"testing"

	nyacrypto "github.com/nyasharp/nyauth/internal/crypto"
)

func TestRecoveryCodesUseSelectorLookupAndArgon2Hashes(t *testing.T) {
	codes, records, err := generateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != recoveryCodeCount || len(records) != recoveryCodeCount {
		t.Fatalf("codes=%d records=%d", len(codes), len(records))
	}
	seen := map[string]bool{}
	for index, code := range codes {
		normalized, selectorHash, ok := parseRecoveryCode(code)
		if !ok {
			t.Fatalf("generated code %q did not parse", code)
		}
		selector := hex.EncodeToString(selectorHash)
		if seen[selector] {
			t.Fatalf("duplicate recovery selector %s", selector)
		}
		seen[selector] = true
		if string(records[index].selectorHash) != string(selectorHash) {
			t.Fatalf("selector hash mismatch for code %d", index)
		}
		verified, err := nyacrypto.VerifyPassword(normalized, records[index].codeHash)
		if err != nil || !verified {
			t.Fatalf("recovery hash %d: verified=%v err=%v", index, verified, err)
		}
		if strings.Contains(records[index].codeHash, normalized) {
			t.Fatalf("recovery code leaked into stored hash")
		}
	}
	for _, invalid := range []string{"", "AAAA", "00000000-0000000000000000", "AAAAAAAA-AAAAAAAAAAAAAAAAA"} {
		if _, _, ok := parseRecoveryCode(invalid); ok {
			t.Fatalf("unexpectedly parsed %q", invalid)
		}
	}
}
