package audit

import (
	"slices"
	"testing"
)

func TestKnownFilterOptionsAreSortedAndUnique(t *testing.T) {
	options := KnownFilterOptions()
	for name, values := range map[string][]string{
		"events": options.Events, "results": options.Results, "risks": options.Risks, "target types": options.TargetTypes,
	} {
		if !slices.IsSorted(values) {
			t.Fatalf("%s are not sorted: %v", name, values)
		}
		for index := 1; index < len(values); index++ {
			if values[index] == values[index-1] {
				t.Fatalf("%s contain duplicate %q", name, values[index])
			}
		}
	}
	for _, targetType := range []string{"oauth_consent", "oauth_endpoint", "oauth_grant"} {
		if !slices.Contains(options.TargetTypes, targetType) {
			t.Fatalf("target types missing runtime value %q: %v", targetType, options.TargetTypes)
		}
	}
}
