package servicecontrol

import (
	"errors"
	"fmt"
	"sort"
)

// Capability identifies one independently controlled runtime operation class.
type Capability string

const (
	CapabilitySelfRegistration Capability = "self_registration"
	CapabilityAccountMutations Capability = "account_mutations"
	CapabilityAdminMutations   Capability = "admin_mutations"
	CapabilityAuthIssuance     Capability = "auth_issuance"
	CapabilityMailDelivery     Capability = "mail_delivery"
	CapabilityMediaWrites      Capability = "media_writes"
)

var (
	ErrUnknownCapability = errors.New("unknown service capability")
	allCapabilities      = []Capability{
		CapabilitySelfRegistration,
		CapabilityAccountMutations,
		CapabilityAdminMutations,
		CapabilityAuthIssuance,
		CapabilityMailDelivery,
		CapabilityMediaWrites,
	}
	capabilityOrder = map[Capability]int{
		CapabilitySelfRegistration: 0,
		CapabilityAccountMutations: 1,
		CapabilityAdminMutations:   2,
		CapabilityAuthIssuance:     3,
		CapabilityMailDelivery:     4,
		CapabilityMediaWrites:      5,
	}
)

// AllCapabilities returns the fixed public capability set in display order.
func AllCapabilities() []Capability {
	return append([]Capability(nil), allCapabilities...)
}

// ParseCapability accepts only the exact persisted/API representation.
func ParseCapability(value string) (Capability, error) {
	capability := Capability(value)
	if !capability.Valid() {
		return "", fmt.Errorf("%w: %q", ErrUnknownCapability, value)
	}
	return capability, nil
}

func (c Capability) Valid() bool {
	_, ok := capabilityOrder[c]
	return ok
}

// NormalizeCapabilities validates, de-duplicates and orders capabilities.
func NormalizeCapabilities(values []Capability) ([]Capability, error) {
	if len(values) == 0 {
		return []Capability{}, nil
	}
	seen := make(map[Capability]struct{}, len(values))
	result := make([]Capability, 0, len(values))
	for _, capability := range values {
		if !capability.Valid() {
			return nil, fmt.Errorf("%w: %q", ErrUnknownCapability, capability)
		}
		if _, exists := seen[capability]; exists {
			continue
		}
		seen[capability] = struct{}{}
		result = append(result, capability)
	}
	sort.Slice(result, func(i, j int) bool {
		return capabilityOrder[result[i]] < capabilityOrder[result[j]]
	})
	return result, nil
}
