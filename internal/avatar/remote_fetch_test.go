package avatar

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"testing"
)

type staticResolver struct {
	addresses []netip.Addr
	err       error
}

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r.addresses...), r.err
}

func TestRemoteFetcherResolveTargetPinsValidatedPublicAddress(t *testing.T) {
	fetcher := NewRemoteFetcher()
	fetcher.resolver = staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	target, err := url.Parse("https://images.example.test/avatar.png")
	if err != nil {
		t.Fatal(err)
	}
	host, address, err := fetcher.resolveTarget(context.Background(), target, map[string]struct{}{"images.example.test": {}})
	if err != nil {
		t.Fatalf("resolveTarget() error = %v", err)
	}
	if host != "images.example.test" || address != "93.184.216.34:443" {
		t.Fatalf("resolved target = %q %q", host, address)
	}
}

func TestRemoteFetcherRejectsUnsafeOrMixedDNSAnswers(t *testing.T) {
	for _, addresses := range [][]netip.Addr{
		{netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("169.254.169.254")},
		{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.10")},
		{netip.MustParseAddr("2001:db8::1")},
	} {
		fetcher := NewRemoteFetcher()
		fetcher.resolver = staticResolver{addresses: addresses}
		target, _ := url.Parse("https://images.example.test/avatar.png")
		_, _, err := fetcher.resolveTarget(context.Background(), target, map[string]struct{}{"images.example.test": {}})
		var permanent *permanentImportError
		if !errors.As(err, &permanent) || permanent.reason != "unsafe_address" {
			t.Fatalf("addresses %v error = %v", addresses, err)
		}
	}
}

func TestRemoteFetcherRejectsUnapprovedTargetShape(t *testing.T) {
	cases := []struct {
		raw    string
		reason string
	}{
		{"http://images.example.test/avatar.png", "invalid_url"},
		{"https://user:pass@images.example.test/avatar.png", "invalid_url"},
		{"https://images.example.test:8443/avatar.png", "invalid_port"},
		{"https://other.example.test/avatar.png", "host_not_allowed"},
		{"https://images.example.test/avatar.png#fragment", "invalid_url"},
	}
	for _, test := range cases {
		t.Run(test.reason+test.raw, func(t *testing.T) {
			fetcher := NewRemoteFetcher()
			fetcher.resolver = staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
			target, _ := url.Parse(test.raw)
			_, _, err := fetcher.resolveTarget(context.Background(), target, map[string]struct{}{"images.example.test": {}})
			var permanent *permanentImportError
			if !errors.As(err, &permanent) || permanent.reason != test.reason {
				t.Fatalf("resolveTarget(%q) error = %v", test.raw, err)
			}
		})
	}
}

func TestSafePublicAddressRejectsReservedRanges(t *testing.T) {
	for _, raw := range []string{"0.0.0.1", "100.64.0.1", "192.0.2.1", "198.18.0.1", "203.0.113.1", "::1", "fc00::1", "fe80::1"} {
		if safePublicAddress(netip.MustParseAddr(raw)) {
			t.Fatalf("safePublicAddress(%s) = true", raw)
		}
	}
	if !safePublicAddress(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public address rejected")
	}
}
