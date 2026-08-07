package oauthstepup

import (
	"errors"
	"testing"
	"time"
)

func TestParseACRValuesAndRequiredContext(t *testing.T) {
	values, err := ParseACRValues(ACRLevel1 + " " + ACRLevel2)
	if err != nil || len(values) != 2 || RequiredContext(values) != ACRLevel1 {
		t.Fatalf("values=%v err=%v", values, err)
	}
	if RequiredContext([]string{ACRLevel2, ACRLevel1}) != ACRLevel2 {
		t.Fatal("ACR client preference order was ignored")
	}
	if _, err := ParseACRValues("urn:example:unknown"); !errors.Is(err, ErrUnsupportedACR) {
		t.Fatalf("unknown acr error=%v", err)
	}
	if _, err := ParseACRValues(ACRLevel1 + " " + ACRLevel1); err == nil {
		t.Fatal("duplicate acr was accepted")
	}
}

func TestParseMaxAgeAndFreshness(t *testing.T) {
	age, err := ParseMaxAge("0")
	if err != nil || age == nil || *age != 0 {
		t.Fatalf("max_age=%v err=%v", age, err)
	}
	for _, raw := range []string{"-1", "+1", "not-a-number", "2592001", "9223372036854775807"} {
		if _, err := ParseMaxAge(raw); err == nil {
			t.Fatalf("invalid max_age %q was accepted", raw)
		}
	}
	now := time.Now().UTC()
	fiveMinutes := 5 * time.Minute
	if !Fresh(now.Add(-fourMinutes), now, &fiveMinutes) || Fresh(now.Add(-sixMinutes), now, &fiveMinutes) {
		t.Fatal("freshness check is incorrect")
	}
}

const (
	fourMinutes = 4 * time.Minute
	sixMinutes  = 6 * time.Minute
)
