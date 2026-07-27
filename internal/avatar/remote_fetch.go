package avatar

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const maxAvatarRedirects = 5

type permanentImportError struct {
	reason string
	err    error
}

func (e *permanentImportError) Error() string { return e.err.Error() }
func (e *permanentImportError) Unwrap() error { return e.err }

func permanentImportFailure(reason string, err error) error {
	return &permanentImportError{reason: reason, err: err}
}

type netIPResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type RemoteFetcher struct {
	resolver netIPResolver
	dialer   net.Dialer
}

func NewRemoteFetcher() *RemoteFetcher {
	return &RemoteFetcher{
		resolver: net.DefaultResolver,
		dialer: net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: -1,
		},
	}
}

func (f *RemoteFetcher) Fetch(ctx context.Context, rawURL string, allowedHosts []string) ([]byte, error) {
	if f == nil || f.resolver == nil {
		return nil, fmt.Errorf("avatar remote fetcher is unavailable")
	}
	allowed := make(map[string]struct{}, len(allowedHosts))
	for _, host := range allowedHosts {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if host != "" {
			allowed[host] = struct{}{}
		}
	}
	current, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, permanentImportFailure("invalid_url", fmt.Errorf("parsing provider avatar URL: %w", err))
	}
	for redirects := 0; ; redirects++ {
		host, address, err := f.resolveTarget(ctx, current, allowed)
		if err != nil {
			return nil, err
		}
		transport := &http.Transport{
			Proxy:               nil,
			DisableKeepAlives:   true,
			ForceAttemptHTTP2:   false,
			TLSHandshakeTimeout: 5 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: host,
			},
			DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
				return f.dialer.DialContext(dialCtx, network, address)
			},
		}
		client := &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			transport.CloseIdleConnections()
			return nil, permanentImportFailure("invalid_url", fmt.Errorf("building provider avatar request: %w", err))
		}
		request.Header.Set("Accept", "image/webp,image/png,image/jpeg")
		request.Header.Set("User-Agent", "nyauth-avatar-import/0.3")
		response, err := client.Do(request)
		if err != nil {
			transport.CloseIdleConnections()
			return nil, fmt.Errorf("fetching provider avatar: %w", err)
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			location := response.Header.Get("Location")
			_ = response.Body.Close()
			transport.CloseIdleConnections()
			if redirects >= maxAvatarRedirects {
				return nil, permanentImportFailure("too_many_redirects", errors.New("provider avatar exceeded redirect limit"))
			}
			next, err := current.Parse(location)
			if err != nil || strings.TrimSpace(location) == "" {
				return nil, permanentImportFailure("invalid_redirect", errors.New("provider avatar returned an invalid redirect"))
			}
			current = next
			continue
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			transport.CloseIdleConnections()
			err := fmt.Errorf("provider avatar returned HTTP %d", response.StatusCode)
			if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
				return nil, err
			}
			return nil, permanentImportFailure("remote_rejected", err)
		}
		if response.ContentLength > MaxUploadBytes {
			_ = response.Body.Close()
			transport.CloseIdleConnections()
			return nil, permanentImportFailure("remote_too_large", ErrImageTooLarge)
		}
		contents, readErr := io.ReadAll(io.LimitReader(response.Body, MaxUploadBytes+1))
		closeErr := response.Body.Close()
		transport.CloseIdleConnections()
		if readErr != nil {
			return nil, fmt.Errorf("reading provider avatar: %w", readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("closing provider avatar response: %w", closeErr)
		}
		if len(contents) > MaxUploadBytes {
			return nil, permanentImportFailure("remote_too_large", ErrImageTooLarge)
		}
		return contents, nil
	}
}

func (f *RemoteFetcher) resolveTarget(ctx context.Context, target *url.URL, allowed map[string]struct{}) (string, string, error) {
	if target == nil || target.Scheme != "https" || target.User != nil || target.Hostname() == "" || target.Fragment != "" {
		return "", "", permanentImportFailure("invalid_url", errors.New("provider avatar URL must be HTTPS without credentials or fragments"))
	}
	if target.Port() != "" && target.Port() != "443" {
		return "", "", permanentImportFailure("invalid_port", errors.New("provider avatar URL must use port 443"))
	}
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	if _, ok := allowed[host]; !ok {
		return "", "", permanentImportFailure("host_not_allowed", errors.New("provider avatar host is not allowed"))
	}
	addresses, err := f.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", "", fmt.Errorf("resolving provider avatar host: %w", err)
	}
	if len(addresses) == 0 {
		return "", "", fmt.Errorf("provider avatar host has no addresses")
	}
	for _, address := range addresses {
		if !safePublicAddress(address) {
			return "", "", permanentImportFailure("unsafe_address", errors.New("provider avatar host resolved to a non-public address"))
		}
	}
	return host, net.JoinHostPort(addresses[0].Unmap().String(), "443"), nil
}

var blockedAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func safePublicAddress(address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range blockedAddressPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
