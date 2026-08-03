package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DiagnosticCheck struct {
	Key                 string `json:"key"`
	Status              string `json:"status"`
	Message             string `json:"message"`
	LatencyMilliseconds int64  `json:"latency_ms"`
}

type ValidationResult struct {
	RunID                      uuid.UUID         `json:"run_id"`
	Provider                   string            `json:"provider"`
	ProviderRevision           int64             `json:"provider_revision"`
	Type                       string            `json:"type"`
	ConfigurationValid         bool              `json:"configuration_valid"`
	AuthorizationEndpointValid bool              `json:"authorization_endpoint_valid"`
	DiscoveryReachable         *bool             `json:"discovery_reachable,omitempty"`
	LatencyMilliseconds        int64             `json:"latency_ms"`
	Message                    string            `json:"message"`
	Checks                     []DiagnosticCheck `json:"checks"`
	CreatedAt                  time.Time         `json:"created_at"`
}

type DiagnosticRun struct {
	ID               uuid.UUID         `json:"id"`
	ProviderRevision int64             `json:"provider_revision"`
	Mode             string            `json:"mode"`
	Result           string            `json:"result"`
	Checks           []DiagnosticCheck `json:"checks"`
	CreatedAt        time.Time         `json:"created_at"`
}

type providerDiagnosticEndpoints struct {
	authorization string
	token         string
	userinfo      string
	jwks          string
	discovery     bool
	client        *http.Client
}

func (m *Manager) StoredProvider(ctx context.Context, name string) (Provider, error) {
	var providerType, clientID, encryptedSecret string
	var scopes []string
	var discoveryURL, authorizationURL, tokenURL, userinfoURL *string
	if err := m.db.QueryRow(ctx, `
		SELECT type,client_id,client_secret,scopes,discovery_url,authorization_url,token_url,userinfo_url
		FROM oauth_providers WHERE name=$1
	`, strings.TrimSpace(name)).Scan(&providerType, &clientID, &encryptedSecret, &scopes, &discoveryURL, &authorizationURL, &tokenURL, &userinfoURL); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProviderNotFound
		}
		return nil, fmt.Errorf("loading stored provider: %w", err)
	}
	secret, err := m.decryptSecret(name, encryptedSecret)
	if err != nil {
		return nil, fmt.Errorf("decrypting stored provider: %w", err)
	}
	return m.providerFromConfig(name, providerType, clientID, secret, scopes,
		valueOrEmpty(discoveryURL), valueOrEmpty(authorizationURL), valueOrEmpty(tokenURL), valueOrEmpty(userinfoURL))
}

// ValidateStoredProvider validates configuration and endpoint reachability.
// Client credentials are intentionally not sent; only an interactive callback
// can prove that the upstream accepts them.
func (m *Manager) ValidateStoredProvider(ctx context.Context, name string) (*ValidationResult, error) {
	return m.ValidateStoredProviderForActor(ctx, name, nil)
}

func (m *Manager) ValidateStoredProviderForActor(ctx context.Context, name string, actorID *uuid.UUID) (*ValidationResult, error) {
	started := time.Now()
	metricResult, metricReason := "failure", "configuration_invalid"
	defer func() { m.recordTelemetry(ctx, "validation", metricResult, metricReason, time.Since(started)) }()
	if m.db == nil {
		metricReason = "database_unavailable"
		return nil, errors.New("provider database is unavailable")
	}
	var providerID uuid.UUID
	var providerType, clientID, encryptedSecret string
	var providerRevision int64
	var scopes []string
	var discoveryURL, authorizationURL, tokenURL, userinfoURL *string
	err := m.db.QueryRow(ctx, `
		SELECT id,type,client_id,client_secret,scopes,discovery_url,authorization_url,token_url,userinfo_url,revision
		FROM oauth_providers WHERE name=$1
	`, name).Scan(&providerID, &providerType, &clientID, &encryptedSecret, &scopes, &discoveryURL, &authorizationURL, &tokenURL, &userinfoURL, &providerRevision)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			metricReason = "not_found"
			return nil, ErrProviderNotFound
		}
		metricReason = "load_failed"
		return nil, fmt.Errorf("loading provider configuration: %w", err)
	}
	result := &ValidationResult{Provider: name, ProviderRevision: providerRevision, Type: providerType, CreatedAt: time.Now().UTC(), Checks: []DiagnosticCheck{}}
	secret, err := m.decryptSecret(name, encryptedSecret)
	if err != nil {
		metricReason = "decrypt_failed"
		return nil, fmt.Errorf("decrypting provider configuration: %w", err)
	}
	configurationStarted := time.Now()
	configured, err := m.providerFromConfig(name, providerType, clientID, secret, scopes,
		valueOrEmpty(discoveryURL), valueOrEmpty(authorizationURL), valueOrEmpty(tokenURL), valueOrEmpty(userinfoURL))
	if err != nil {
		result.Checks = append(result.Checks, diagnosticCheck("configuration", false, "配置或 Discovery 校验失败", configurationStarted))
		result.Message = "provider configuration validation failed"
		result.LatencyMilliseconds = time.Since(started).Milliseconds()
		if persistErr := m.persistDiagnosticRun(ctx, providerID, providerRevision, "preflight", result.Checks, actorID, result); persistErr != nil {
			return nil, persistErr
		}
		return result, nil
	}
	result.ConfigurationValid = true
	result.Checks = append(result.Checks, diagnosticCheck("configuration", true, "配置可解析，密钥可解密", configurationStarted))
	endpoints := diagnosticEndpoints(configured)
	authorizationStarted := time.Now()
	authorization := configured.AuthorizationURL("validation-state", "validation-nonce", "https://invalid.example/callback")
	parsed, parseErr := url.Parse(authorization)
	result.AuthorizationEndpointValid = parseErr == nil && parsed.Scheme == "https" && parsed.Host != ""
	result.Checks = append(result.Checks, diagnosticCheck("authorization_endpoint", result.AuthorizationEndpointValid, map[bool]string{true: "授权地址格式有效", false: "授权地址无效或未使用 HTTPS"}[result.AuthorizationEndpointValid], authorizationStarted))
	if endpoints.discovery {
		reachable := true
		result.DiscoveryReachable = &reachable
		result.Checks = append(result.Checks, DiagnosticCheck{Key: "discovery", Status: "passed", Message: "Discovery 文档可达且字段有效"})
	}

	probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	checks := probeProviderEndpoints(probeCtx, endpoints)
	result.Checks = append(result.Checks, checks...)
	passed := result.AuthorizationEndpointValid
	for _, check := range result.Checks {
		if check.Status == "failed" {
			passed = false
		}
	}
	if passed {
		result.Message = "configuration and upstream endpoints are reachable; credentials require an interactive test"
		metricResult, metricReason = "success", "none"
	} else {
		result.Message = "one or more provider checks failed"
		metricReason = "endpoint_unavailable"
	}
	result.LatencyMilliseconds = time.Since(started).Milliseconds()
	if err := m.persistDiagnosticRun(ctx, providerID, providerRevision, "preflight", result.Checks, actorID, result); err != nil {
		return nil, err
	}
	return result, nil
}

func diagnosticEndpoints(configured Provider) providerDiagnosticEndpoints {
	switch value := configured.(type) {
	case *GitHub:
		return providerDiagnosticEndpoints{authorization: value.authURL, token: value.tokenURL, userinfo: value.userURL, client: value.client}
	case *Google:
		return oidcDiagnosticEndpoints(value.GenericOIDC, false)
	case *GenericOIDC:
		return oidcDiagnosticEndpoints(value, true)
	default:
		return providerDiagnosticEndpoints{client: http.DefaultClient}
	}
}

func oidcDiagnosticEndpoints(configured *GenericOIDC, discovery bool) providerDiagnosticEndpoints {
	return providerDiagnosticEndpoints{
		authorization: configured.authorizationURL, token: configured.tokenURL, userinfo: configured.userinfoURL,
		jwks: configured.jwksURL, discovery: discovery, client: configured.client,
	}
}

func probeProviderEndpoints(ctx context.Context, endpoints providerDiagnosticEndpoints) []DiagnosticCheck {
	type probe struct {
		key, endpoint string
		requireJWKS   bool
	}
	probes := []probe{{"token_endpoint", endpoints.token, false}, {"userinfo_endpoint", endpoints.userinfo, false}, {"jwks_endpoint", endpoints.jwks, true}}
	results := make([]DiagnosticCheck, len(probes))
	var wait sync.WaitGroup
	for index, current := range probes {
		if current.endpoint == "" {
			results[index] = DiagnosticCheck{Key: current.key, Status: "skipped", Message: "此 Provider 不使用该端点"}
			continue
		}
		wait.Add(1)
		go func(index int, current probe) {
			defer wait.Done()
			results[index] = probeProviderEndpoint(ctx, endpoints.client, current.key, current.endpoint, current.requireJWKS)
		}(index, current)
	}
	wait.Wait()
	return results
}

func probeProviderEndpoint(ctx context.Context, client *http.Client, key, endpoint string, requireJWKS bool) DiagnosticCheck {
	started := time.Now()
	fail := func(message string) DiagnosticCheck { return diagnosticCheck(key, false, message, started) }
	if err := validateHTTPSURL(endpoint); err != nil {
		return fail("端点地址无效或未使用 HTTPS")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fail("无法创建端点请求")
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return fail("端点连接失败")
	}
	defer response.Body.Close()
	if requireJWKS {
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return fail(fmt.Sprintf("JWKS 端点返回 HTTP %d", response.StatusCode))
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, maxProviderResponseSize+1))
		if err != nil || len(body) > maxProviderResponseSize {
			return fail("JWKS 响应不可读取")
		}
		var document struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if json.Unmarshal(body, &document) != nil || len(document.Keys) == 0 {
			return fail("JWKS 响应不包含可用密钥")
		}
		return diagnosticCheck(key, true, "JWKS 可达且包含签名密钥", started)
	}
	if response.StatusCode >= 500 {
		return fail(fmt.Sprintf("端点返回 HTTP %d", response.StatusCode))
	}
	return diagnosticCheck(key, true, fmt.Sprintf("端点可达（HTTP %d）", response.StatusCode), started)
}

func diagnosticCheck(key string, passed bool, message string, started time.Time) DiagnosticCheck {
	status := "failed"
	if passed {
		status = "passed"
	}
	return DiagnosticCheck{Key: key, Status: status, Message: message, LatencyMilliseconds: time.Since(started).Milliseconds()}
}

func (m *Manager) persistDiagnosticRun(ctx context.Context, providerID uuid.UUID, revision int64, mode string, checks []DiagnosticCheck, actorID *uuid.UUID, result *ValidationResult) error {
	run, err := m.insertDiagnosticRun(ctx, providerID, revision, mode, checks, actorID)
	if err != nil {
		return err
	}
	result.RunID, result.CreatedAt = run.ID, run.CreatedAt
	return nil
}

func (m *Manager) insertDiagnosticRun(ctx context.Context, providerID uuid.UUID, revision int64, mode string, checks []DiagnosticCheck, actorID *uuid.UUID) (*DiagnosticRun, error) {
	encoded, err := json.Marshal(checks)
	if err != nil {
		return nil, fmt.Errorf("encoding provider diagnostic checks: %w", err)
	}
	status := "success"
	for _, check := range checks {
		if check.Status == "failed" {
			status = "failure"
			break
		}
	}
	var actor any
	if actorID != nil && *actorID != uuid.Nil {
		actor = *actorID
	}
	run := &DiagnosticRun{ProviderRevision: revision, Mode: mode, Result: status, Checks: append([]DiagnosticCheck(nil), checks...)}
	if err := m.db.QueryRow(ctx, `
		INSERT INTO provider_diagnostic_runs (provider_id,provider_revision,mode,result,checks,initiated_by)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,created_at
	`, providerID, revision, mode, status, string(encoded), actor).Scan(&run.ID, &run.CreatedAt); err != nil {
		return nil, fmt.Errorf("persisting provider diagnostic run: %w", err)
	}
	return run, nil
}

func (m *Manager) RecordInteractiveDiagnostic(ctx context.Context, name string, actorID uuid.UUID, checks []DiagnosticCheck) (*DiagnosticRun, error) {
	var providerID uuid.UUID
	var revision int64
	if err := m.db.QueryRow(ctx, `SELECT id,revision FROM oauth_providers WHERE name=$1`, strings.TrimSpace(name)).Scan(&providerID, &revision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProviderNotFound
		}
		return nil, fmt.Errorf("loading provider for interactive diagnostic: %w", err)
	}
	return m.insertDiagnosticRun(ctx, providerID, revision, "interactive", checks, &actorID)
}

func (m *Manager) ListDiagnosticRuns(ctx context.Context, name string, limit int) ([]DiagnosticRun, error) {
	if limit < 1 {
		limit = 10
	}
	if limit > 50 {
		limit = 50
	}
	var providerID uuid.UUID
	if err := m.db.QueryRow(ctx, `SELECT id FROM oauth_providers WHERE name=$1`, strings.TrimSpace(name)).Scan(&providerID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProviderNotFound
		}
		return nil, fmt.Errorf("loading provider for diagnostic history: %w", err)
	}
	rows, err := m.db.Query(ctx, `
		SELECT run.id,run.provider_revision,run.mode,run.result,run.checks,run.created_at
		FROM provider_diagnostic_runs run
		WHERE run.provider_id=$1 ORDER BY run.created_at DESC,run.id DESC LIMIT $2
	`, providerID, limit)
	if err != nil {
		return nil, fmt.Errorf("listing provider diagnostic runs: %w", err)
	}
	defer rows.Close()
	items := make([]DiagnosticRun, 0, limit)
	for rows.Next() {
		var item DiagnosticRun
		var encoded []byte
		if err := rows.Scan(&item.ID, &item.ProviderRevision, &item.Mode, &item.Result, &encoded, &item.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(encoded, &item.Checks); err != nil {
			return nil, fmt.Errorf("decoding provider diagnostic checks: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func CleanupDiagnosticRuns(ctx context.Context, db *pgxpool.Pool, before time.Time) (int64, error) {
	if db == nil {
		return 0, errors.New("provider database is unavailable")
	}
	result, err := db.Exec(ctx, `DELETE FROM provider_diagnostic_runs WHERE created_at < $1`, before.UTC())
	if err != nil {
		return 0, fmt.Errorf("cleaning provider diagnostic runs: %w", err)
	}
	return result.RowsAffected(), nil
}
