package servicecontrol

import (
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestParseAndNormalizeCapabilities(t *testing.T) {
	for _, capability := range AllCapabilities() {
		parsed, err := ParseCapability(string(capability))
		if err != nil || parsed != capability {
			t.Fatalf("ParseCapability(%q) = %q, %v", capability, parsed, err)
		}
	}
	for _, invalid := range []string{"", " self_registration", "self_registration ", "unknown"} {
		if _, err := ParseCapability(invalid); !errors.Is(err, ErrUnknownCapability) {
			t.Fatalf("ParseCapability(%q) error = %v, want ErrUnknownCapability", invalid, err)
		}
	}

	normalized, err := NormalizeCapabilities([]Capability{
		CapabilityMediaWrites, CapabilitySelfRegistration, CapabilityMediaWrites,
	})
	if err != nil {
		t.Fatalf("NormalizeCapabilities: %v", err)
	}
	want := []Capability{CapabilitySelfRegistration, CapabilityMediaWrites}
	if !reflect.DeepEqual(normalized, want) {
		t.Fatalf("normalized capabilities = %v, want %v", normalized, want)
	}
	if _, err := NormalizeCapabilities([]Capability{"future_capability"}); !errors.Is(err, ErrUnknownCapability) {
		t.Fatalf("unknown normalized capability error = %v", err)
	}

	copyOfAll := AllCapabilities()
	copyOfAll[0] = CapabilityMediaWrites
	if AllCapabilities()[0] != CapabilitySelfRegistration {
		t.Fatal("AllCapabilities exposed mutable package state")
	}
}

func TestNormalizeUpdateInputTrimsBeforeReasonValidation(t *testing.T) {
	input := normalizeUpdateInput(UpdateInput{
		ExpectedRevision:   1,
		PausedCapabilities: []Capability{CapabilityAccountMutations},
		PublicMessage:      "  planned work  ", InternalReason: "   ",
		UpdatedBy: uuid.New(), UpdatedByName: "  operator  ",
	})
	if input.PublicMessage != "planned work" || input.UpdatedByName != "operator" || input.InternalReason != "" {
		t.Fatalf("normalized input = %#v", input)
	}
	if _, err := validateUpdateInput(input); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("blank normalized reason error = %v, want ErrInvalidState", err)
	}
}
