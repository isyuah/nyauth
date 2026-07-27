package provider

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

var ErrInvalidAvatarPolicy = errors.New("invalid provider avatar policy")

var builtInAvatarHosts = map[string][]string{
	"github": {"avatars.githubusercontent.com"},
	"google": {"lh3.googleusercontent.com"},
}

// NormalizeAvatarPolicy validates the static egress boundary used when a
// provider is allowed to seed a newly-created account's first avatar.
func NormalizeAvatarPolicy(providerType string, enabled bool, hosts []string) ([]string, error) {
	if providerType == "github" || providerType == "google" {
		if len(hosts) != 0 {
			return nil, fmt.Errorf("%w: %s uses a built-in avatar host allowlist", ErrInvalidAvatarPolicy, providerType)
		}
		return []string{}, nil
	}
	if providerType != "generic" {
		return nil, fmt.Errorf("%w: unsupported provider type", ErrInvalidAvatarPolicy)
	}

	seen := make(map[string]struct{}, len(hosts))
	normalized := make([]string, 0, len(hosts))
	for _, raw := range hosts {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if host == "" || strings.ContainsAny(host, "/:@[]* ") || net.ParseIP(host) != nil ||
			host == "localhost" || strings.HasSuffix(host, ".localhost") || !strings.Contains(host, ".") {
			return nil, fmt.Errorf("%w: avatar hosts must be exact public DNS names", ErrInvalidAvatarPolicy)
		}
		for _, r := range host {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
				continue
			}
			return nil, fmt.Errorf("%w: avatar hosts must use ASCII DNS syntax", ErrInvalidAvatarPolicy)
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		normalized = append(normalized, host)
	}
	if enabled && len(normalized) == 0 {
		return nil, fmt.Errorf("%w: generic OIDC avatar import requires at least one allowed host", ErrInvalidAvatarPolicy)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func BuiltInAvatarHosts(providerType string) []string {
	return append([]string(nil), builtInAvatarHosts[providerType]...)
}
