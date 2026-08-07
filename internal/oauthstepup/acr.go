// Package oauthstepup contains the bounded authentication-context vocabulary
// used by the OAuth Step-Up implementation. The values are deliberately
// application-defined ACR URIs; RFC 9470 defines how they are requested and
// challenged, not what a deployment's assurance levels mean.
package oauthstepup

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	ACRLevel1 = "urn:nyauth:loa:1"
	ACRLevel2 = "urn:nyauth:loa:2"

	MaxACRValues = 4
	MaxAge       = 30 * 24 * time.Hour
)

var ErrUnsupportedACR = errors.New("unsupported authentication context")

// AuthenticationContext describes the assurance reached by a browser
// authentication event. Empty and unknown persisted values are treated as
// level 1 for backwards compatibility, never as level 2.
type AuthenticationContext string

func (c AuthenticationContext) String() string {
	if c == ACRLevel2 {
		return ACRLevel2
	}
	return ACRLevel1
}

func NormalizeContext(value string) AuthenticationContext {
	if strings.TrimSpace(value) == ACRLevel2 {
		return AuthenticationContext(ACRLevel2)
	}
	return AuthenticationContext(ACRLevel1)
}

func (c AuthenticationContext) Satisfies(required string) bool {
	switch strings.TrimSpace(required) {
	case "", ACRLevel1:
		return true
	case ACRLevel2:
		return c == AuthenticationContext(ACRLevel2)
	default:
		return false
	}
}

// ParseACRValues validates the space-separated RFC 9470/OIDC request value.
// Nyauth intentionally exposes only its documented assurance vocabulary.
func ParseACRValues(raw string) ([]string, error) {
	fields := strings.Fields(raw)
	if len(fields) > MaxACRValues {
		return nil, fmt.Errorf("too many authentication context values")
	}
	if len(fields) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(fields))
	values := make([]string, 0, len(fields))
	for _, value := range fields {
		if value != ACRLevel1 && value != ACRLevel2 {
			return nil, ErrUnsupportedACR
		}
		if _, ok := seen[value]; ok {
			return nil, fmt.Errorf("duplicate authentication context")
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values, nil
}

// RequiredContext selects the first supported context because acr_values is
// ordered by client preference. A client that strictly requires level 2 must
// request level 2 without listing level 1 first.
func RequiredContext(values []string) string {
	for _, value := range values {
		if value == ACRLevel1 || value == ACRLevel2 {
			return value
		}
	}
	return ""
}

// ParseMaxAge parses the non-negative seconds form defined by OIDC and used
// by RFC 9470. A finite upper bound prevents an untrusted request from
// creating an effectively unbounded authorization continuation.
func ParseMaxAge(raw string) (*time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if strings.HasPrefix(raw, "+") || strings.HasPrefix(raw, "-") {
		return nil, errors.New("max_age must be a non-negative integer")
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds < 0 {
		return nil, errors.New("max_age must be a non-negative integer")
	}
	if seconds > int64(MaxAge/time.Second) {
		return nil, fmt.Errorf("max_age must be at most %s", MaxAge)
	}
	age := time.Duration(seconds) * time.Second
	return &age, nil
}

func Fresh(authenticatedAt, now time.Time, maxAge *time.Duration) bool {
	if maxAge == nil {
		return true
	}
	if authenticatedAt.IsZero() || authenticatedAt.After(now.Add(time.Minute)) {
		return false
	}
	return now.Sub(authenticatedAt) <= *maxAge
}
