package provider

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var providerIconKeys = map[string]struct{}{
	"auto": {}, "github": {}, "google": {}, "key": {}, "link": {}, "globe": {},
}

var ErrInvalidPresentation = errors.New("invalid provider presentation")

func normalizePresentation(name, displayName, iconKey string) (string, string, error) {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		displayName = name
	}
	if utf8.RuneCountInString(displayName) > 100 {
		return "", "", fmt.Errorf("%w: display_name must contain at most 100 characters", ErrInvalidPresentation)
	}
	iconKey = strings.ToLower(strings.TrimSpace(iconKey))
	if iconKey == "" {
		iconKey = "auto"
	}
	if _, ok := providerIconKeys[iconKey]; !ok {
		return "", "", fmt.Errorf("%w: unsupported icon_key", ErrInvalidPresentation)
	}
	return displayName, iconKey, nil
}
