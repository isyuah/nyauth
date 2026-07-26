package provider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
)

type ValidationResult struct {
	Provider                   string `json:"provider"`
	Type                       string `json:"type"`
	ConfigurationValid         bool   `json:"configuration_valid"`
	AuthorizationEndpointValid bool   `json:"authorization_endpoint_valid"`
	DiscoveryReachable         *bool  `json:"discovery_reachable,omitempty"`
	LatencyMilliseconds        int64  `json:"latency_ms"`
	Message                    string `json:"message"`
}

// ValidateStoredProvider validates persisted configuration without claiming
// that the upstream client credentials have authenticated successfully. A
// real authorization callback is the only proof that credentials work.
func (m *Manager) ValidateStoredProvider(ctx context.Context, name string) (*ValidationResult, error) {
	started := time.Now()
	metricResult, metricReason := "failure", "configuration_invalid"
	defer func() {
		m.recordTelemetry(ctx, "validation", metricResult, metricReason, time.Since(started))
	}()
	if m.db == nil {
		metricReason = "database_unavailable"
		return nil, errors.New("provider database is unavailable")
	}
	var providerType, clientID, encryptedSecret string
	var scopes []string
	var discoveryURL, authorizationURL, tokenURL, userinfoURL *string
	err := m.db.QueryRow(ctx, `
		SELECT type,client_id,client_secret,scopes,discovery_url,authorization_url,token_url,userinfo_url
		FROM oauth_providers WHERE name=$1
	`, name).Scan(&providerType, &clientID, &encryptedSecret, &scopes, &discoveryURL, &authorizationURL, &tokenURL, &userinfoURL)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			metricReason = "not_found"
			return nil, ErrProviderNotFound
		}
		metricReason = "load_failed"
		return nil, fmt.Errorf("loading provider configuration: %w", err)
	}
	secret, err := m.decryptSecret(name, encryptedSecret)
	if err != nil {
		metricReason = "decrypt_failed"
		return nil, fmt.Errorf("decrypting provider configuration: %w", err)
	}
	configured, err := m.providerFromConfig(name, providerType, clientID, secret, scopes,
		valueOrEmpty(discoveryURL), valueOrEmpty(authorizationURL), valueOrEmpty(tokenURL), valueOrEmpty(userinfoURL))
	if err != nil {
		return &ValidationResult{Provider: name, Type: providerType, LatencyMilliseconds: time.Since(started).Milliseconds(), Message: "configuration validation failed"}, nil
	}
	authorization := configured.AuthorizationURL("validation-state", "validation-nonce", "https://invalid.example/callback")
	parsed, parseErr := url.Parse(authorization)
	authorizationValid := parseErr == nil && parsed.Scheme == "https" && parsed.Host != ""
	result := &ValidationResult{
		Provider: name, Type: providerType, ConfigurationValid: true,
		AuthorizationEndpointValid: authorizationValid,
		LatencyMilliseconds:        time.Since(started).Milliseconds(),
		Message:                    "configuration is valid; client credentials are verified only by a real login",
	}
	if providerType == "generic" {
		reachable := true // providerFromConfig completed strict HTTPS discovery.
		result.DiscoveryReachable = &reachable
	}
	if !authorizationValid {
		result.ConfigurationValid = false
		result.Message = "authorization endpoint is invalid"
		metricReason = "endpoint_invalid"
		return result, nil
	}
	metricResult, metricReason = "success", "none"
	return result, nil
}
