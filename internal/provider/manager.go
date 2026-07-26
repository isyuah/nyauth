package provider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

const providerSecretPurpose = "provider-client-secret"

var (
	ErrProviderNotFound         = errors.New("provider not found")
	ErrProviderRevisionConflict = errors.New("provider was changed concurrently")
)

type TelemetrySink func(context.Context, string, string, string, string, time.Duration)

// Manager owns an immutable-at-read-time snapshot of enabled providers.
type Manager struct {
	mutationMu       sync.Mutex
	mu               sync.RWMutex
	providers        map[string]Provider
	db               *pgxpool.Pool
	masterKeys       map[string][]byte
	activeKeyID      string
	production       bool
	snapshotRevision atomic.Uint64
	ready            atomic.Bool
	telemetryMu      sync.RWMutex
	telemetrySink    TelemetrySink
}

// NewManager creates a provider manager. The optional production flag enables
// private-network egress blocking for generic discovery providers.
func NewManager(db *pgxpool.Pool, masterKey []byte, production ...bool) *Manager {
	isProduction := len(production) > 0 && production[0]
	keyCopy := append([]byte(nil), masterKey...)
	return &Manager{
		providers: make(map[string]Provider),
		db:        db, masterKeys: map[string][]byte{"primary": keyCopy}, activeKeyID: "primary",
		production: isProduction,
	}
}

func (m *Manager) SetTelemetrySink(sink TelemetrySink) {
	if m != nil {
		m.telemetryMu.Lock()
		m.telemetrySink = sink
		m.telemetryMu.Unlock()
	}
}

func (m *Manager) recordTelemetry(ctx context.Context, operation, result, reason string, duration time.Duration) {
	if m == nil {
		return
	}
	m.telemetryMu.RLock()
	sink := m.telemetrySink
	m.telemetryMu.RUnlock()
	if sink != nil {
		sink(ctx, operation, "none", result, reason, duration)
	}
}

// NewManagerWithKeyring supports decrypting old envelopes during master-key
// rotation while using activeKeyID for all new provider secrets.
func NewManagerWithKeyring(db *pgxpool.Pool, masterKeys map[string][]byte, activeKeyID string, production bool) (*Manager, error) {
	activeKey, ok := masterKeys[activeKeyID]
	if !ok {
		return nil, fmt.Errorf("active provider envelope key %q is unavailable", activeKeyID)
	}
	if len(activeKey) != 32 {
		return nil, errors.New("active provider envelope key must be exactly 32 bytes")
	}
	keys := make(map[string][]byte, len(masterKeys))
	for keyID, key := range masterKeys {
		keys[keyID] = append([]byte(nil), key...)
	}
	return &Manager{
		providers: make(map[string]Provider),
		db:        db, masterKeys: keys, activeKeyID: activeKeyID, production: production,
	}, nil
}

// LoadDynamic atomically replaces the runtime snapshot with currently enabled
// database providers. Disabled and deleted providers are removed immediately.
func (m *Manager) LoadDynamic(ctx context.Context) error {
	started := time.Now()
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	err := m.loadDynamic(ctx)
	if err != nil {
		m.recordTelemetry(ctx, "synchronization", "failure", "load_failed", time.Since(started))
		return err
	}
	m.recordTelemetry(ctx, "synchronization", "success", "none", time.Since(started))
	return nil
}

func (m *Manager) loadDynamic(ctx context.Context) error {
	if m.db == nil {
		m.ready.Store(true)
		return nil
	}
	rows, err := m.db.Query(ctx, `
		SELECT name, type, client_id, client_secret, scopes, discovery_url, authorization_url, token_url, userinfo_url, enabled
		FROM oauth_providers
	`)
	if err != nil {
		return fmt.Errorf("querying providers: %w", err)
	}
	defer rows.Close()

	dynamicProviders := make(map[string]Provider)
	for rows.Next() {
		var name, providerType, clientID, encryptedSecret string
		var enabled bool
		var scopes []string
		var discoveryURL, authorizationURL, tokenURL, userinfoURL *string
		if err := rows.Scan(&name, &providerType, &clientID, &encryptedSecret, &scopes, &discoveryURL, &authorizationURL, &tokenURL, &userinfoURL, &enabled); err != nil {
			return fmt.Errorf("scanning provider: %w", err)
		}
		if !enabled {
			continue
		}
		secret, err := m.decryptSecret(name, encryptedSecret)
		if err != nil {
			return fmt.Errorf("decrypting secret for %s: %w", name, err)
		}
		configured, err := m.providerFromConfig(name, providerType, clientID, secret, scopes,
			valueOrEmpty(discoveryURL), valueOrEmpty(authorizationURL), valueOrEmpty(tokenURL), valueOrEmpty(userinfoURL))
		if err != nil {
			return fmt.Errorf("loading provider %s: %w", name, err)
		}
		dynamicProviders[name] = configured
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating providers: %w", err)
	}

	m.mu.Lock()
	m.providers = dynamicProviders
	m.mu.Unlock()
	m.snapshotRevision.Add(1)
	m.ready.Store(true)
	return nil
}

func (m *Manager) providerFromConfig(name, providerType, clientID, clientSecret string, scopes []string, discoveryURL, authorizationURL, tokenURL, userinfoURL string) (Provider, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	if clientID == "" || clientSecret == "" {
		return nil, errors.New("provider client ID and client secret are required")
	}
	switch providerType {
	case "github":
		return NewGitHubWithMode(name, clientID, clientSecret, scopes, m.production), nil
	case "google":
		return NewGoogleWithMode(name, clientID, clientSecret, scopes, m.production), nil
	case "generic":
		if discoveryURL == "" {
			return nil, errors.New("generic OIDC providers require an HTTPS discovery URL")
		}
		return NewGenericOIDCWithMode(name, clientID, clientSecret, scopes, discoveryURL, m.production)
	default:
		return nil, fmt.Errorf("unsupported provider type %q", providerType)
	}
}

// ValidateName keeps provider identifiers safe as a single URL path segment.
func ValidateName(name string) error {
	if len(name) == 0 || len(name) > 64 {
		return errors.New("provider name must be 1 to 64 characters")
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return errors.New("provider name may contain only letters, numbers, dot, underscore, and hyphen")
	}
	return nil
}

func (m *Manager) Get(name string) (Provider, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	configured, ok := m.providers[name]
	return configured, ok
}

func (m *Manager) List() []ProviderInfo {
	m.mu.RLock()
	list := make([]ProviderInfo, 0, len(m.providers))
	for _, configured := range m.providers {
		list = append(list, ProviderInfo{Name: configured.Name(), Type: configured.Type()})
	}
	m.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

type ProviderInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func (m *Manager) CreateProvider(ctx context.Context, req models.CreateProviderRequest, mutation audit.MutationAudit) (*models.ExternalProvider, error) {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	if err := mutation.ValidateEvent(models.AuditProviderCreated); err != nil {
		return nil, fmt.Errorf("invalid provider creation audit context: %w", err)
	}
	if m.db == nil {
		return nil, errors.New("provider database is unavailable")
	}
	if req.Enabled == nil {
		return nil, errors.New("provider enabled state must be explicitly set")
	}
	runtimeProvider, err := m.providerFromConfig(req.Name, req.Type, req.ClientID, req.ClientSecret, req.Scopes,
		req.DiscoveryURL, req.AuthorizationURL, req.TokenURL, req.UserinfoURL)
	if err != nil {
		return nil, fmt.Errorf("validating provider: %w", err)
	}
	encryptedSecret, err := m.EncryptSecret(req.Name, req.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("encrypting secret: %w", err)
	}
	configured := &models.ExternalProvider{
		Name: req.Name, Type: req.Type, ClientID: req.ClientID,
		ClientSecret: encryptedSecret, Scopes: req.Scopes, Enabled: *req.Enabled,
	}
	if req.DiscoveryURL != "" {
		configured.DiscoveryURL = &req.DiscoveryURL
	}
	if req.AuthorizationURL != "" {
		configured.AuthorizationURL = &req.AuthorizationURL
	}
	if req.TokenURL != "" {
		configured.TokenURL = &req.TokenURL
	}
	if req.UserinfoURL != "" {
		configured.UserinfoURL = &req.UserinfoURL
	}
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting provider creation: %w", err)
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `
		INSERT INTO oauth_providers (name, type, client_id, client_secret, scopes, discovery_url, authorization_url, token_url, userinfo_url, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id,revision,metadata,created_at,updated_at
	`, configured.Name, configured.Type, configured.ClientID, configured.ClientSecret, configured.Scopes,
		configured.DiscoveryURL, configured.AuthorizationURL, configured.TokenURL, configured.UserinfoURL, configured.Enabled).
		Scan(&configured.ID, &configured.Revision, &configured.Metadata, &configured.CreatedAt, &configured.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("inserting provider: %w", err)
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("provider", configured.Name)); err != nil {
		return nil, fmt.Errorf("auditing provider creation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing provider creation: %w", err)
	}
	m.setDynamicProvider(req.Name, runtimeProvider, configured.Enabled)
	m.notifyChange(ctx, req.Name, "created")
	return configured, nil
}

// UpdateProvider validates the complete candidate before persisting it.
func (m *Manager) UpdateProvider(ctx context.Context, name string, req models.UpdateProviderRequest, mutation audit.MutationAudit) (*models.ExternalProvider, error) {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	if err := mutation.ValidateEvent(models.AuditProviderUpdated); err != nil {
		return nil, fmt.Errorf("invalid provider update audit context: %w", err)
	}
	if m.db == nil {
		return nil, errors.New("provider database is unavailable")
	}
	var current models.ExternalProvider
	var encryptedSecret string
	err := m.db.QueryRow(ctx, `
		SELECT id,name,type,client_id,client_secret,scopes,discovery_url,authorization_url,
		       token_url,userinfo_url,enabled,revision,metadata,created_at,updated_at
		FROM oauth_providers WHERE name=$1
	`, name).Scan(&current.ID, &current.Name, &current.Type, &current.ClientID, &encryptedSecret,
		&current.Scopes, &current.DiscoveryURL, &current.AuthorizationURL, &current.TokenURL,
		&current.UserinfoURL, &current.Enabled, &current.Revision, &current.Metadata, &current.CreatedAt, &current.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProviderNotFound
		}
		return nil, fmt.Errorf("getting provider: %w", err)
	}
	plaintextSecret := ""
	plaintextAvailable := false
	if req.ClientID != nil {
		current.ClientID = *req.ClientID
	}
	if req.ClientSecret != nil {
		plaintextSecret = *req.ClientSecret
		plaintextAvailable = true
	}
	if req.Scopes != nil {
		current.Scopes = req.Scopes
	}
	if req.DiscoveryURL != nil {
		current.DiscoveryURL = req.DiscoveryURL
	}
	if req.AuthorizationURL != nil {
		current.AuthorizationURL = req.AuthorizationURL
	}
	if req.TokenURL != nil {
		current.TokenURL = req.TokenURL
	}
	if req.UserinfoURL != nil {
		current.UserinfoURL = req.UserinfoURL
	}
	if req.Enabled != nil {
		current.Enabled = *req.Enabled
	}
	var runtimeProvider Provider
	if current.Enabled {
		if !plaintextAvailable {
			plaintextSecret, err = m.decryptSecret(name, encryptedSecret)
			if err != nil {
				return nil, fmt.Errorf("decrypting provider secret: %w", err)
			}
		}
		runtimeProvider, err = m.providerFromConfig(name, current.Type, current.ClientID, plaintextSecret,
			current.Scopes, valueOrEmpty(current.DiscoveryURL), valueOrEmpty(current.AuthorizationURL),
			valueOrEmpty(current.TokenURL), valueOrEmpty(current.UserinfoURL))
		if err != nil {
			return nil, fmt.Errorf("validating provider: %w", err)
		}
	}
	if req.ClientSecret != nil {
		encryptedSecret, err = m.EncryptSecret(name, plaintextSecret)
		if err != nil {
			return nil, fmt.Errorf("encrypting provider secret: %w", err)
		}
	}
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting provider update: %w", err)
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `
		UPDATE oauth_providers SET client_id=$2,client_secret=$3,scopes=$4,discovery_url=$5,
		       authorization_url=$6,token_url=$7,userinfo_url=$8,enabled=$9,
		       revision=revision+1,updated_at=NOW()
		WHERE name=$1 AND revision=$10
		RETURNING revision,updated_at
	`, name, current.ClientID, encryptedSecret, current.Scopes, current.DiscoveryURL,
		current.AuthorizationURL, current.TokenURL, current.UserinfoURL, current.Enabled, current.Revision).
		Scan(&current.Revision, &current.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			var exists bool
			if existsErr := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM oauth_providers WHERE name=$1)`, name).Scan(&exists); existsErr != nil {
				return nil, fmt.Errorf("checking provider revision: %w", existsErr)
			}
			if !exists {
				return nil, ErrProviderNotFound
			}
			return nil, ErrProviderRevisionConflict
		}
		return nil, fmt.Errorf("updating provider: %w", err)
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("provider", name)); err != nil {
		return nil, fmt.Errorf("auditing provider update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing provider update: %w", err)
	}
	m.setDynamicProvider(name, runtimeProvider, current.Enabled)
	m.notifyChange(ctx, name, "updated")
	return &current, nil
}

func (m *Manager) DeleteProvider(ctx context.Context, name string, mutation audit.MutationAudit) error {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	if err := mutation.ValidateEvent(models.AuditProviderDeleted); err != nil {
		return fmt.Errorf("invalid provider deletion audit context: %w", err)
	}
	if m.db == nil {
		return errors.New("provider database is unavailable")
	}
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting provider deletion: %w", err)
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `DELETE FROM oauth_providers WHERE name=$1`, name)
	if err != nil {
		return fmt.Errorf("deleting provider: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrProviderNotFound
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("provider", name)); err != nil {
		return fmt.Errorf("auditing provider deletion: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing provider deletion: %w", err)
	}
	m.removeDynamicProvider(name)
	m.notifyChange(ctx, name, "deleted")
	return nil
}

// setDynamicProvider updates one runtime entry after its database mutation has
// committed.
func (m *Manager) setDynamicProvider(name string, configured Provider, enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if enabled {
		m.providers[name] = configured
		m.snapshotRevision.Add(1)
		m.ready.Store(true)
		return
	}
	delete(m.providers, name)
	m.snapshotRevision.Add(1)
	m.ready.Store(true)
}

func (m *Manager) removeDynamicProvider(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.providers, name)
	m.snapshotRevision.Add(1)
	m.ready.Store(true)
}

func (m *Manager) Ready() bool { return m.ready.Load() }

func (m *Manager) SnapshotRevision() uint64 { return m.snapshotRevision.Load() }

func (m *Manager) notifyChange(ctx context.Context, name, action string) {
	if m.db == nil {
		return
	}
	if _, err := m.db.Exec(ctx, `SELECT pg_notify('nyauth_provider_changed', $1)`, action+":"+name); err != nil {
		m.recordTelemetry(ctx, "synchronization", "failure", "notification_publish_failed", 0)
		slog.ErrorContext(ctx, "provider change notification failed", "provider", name, "action", action, "error", err)
	}
}

// EncryptSecret creates the only accepted persisted representation of a
// provider secret. The provider name is authenticated as envelope AAD.
func (m *Manager) EncryptSecret(providerName, plaintext string) (string, error) {
	key, ok := m.masterKeys[m.activeKeyID]
	if !ok {
		return "", errors.New("active provider encryption key is unavailable")
	}
	return crypto.EncryptEnvelope(key, m.activeKeyID, providerSecretPurpose, []byte(plaintext), []byte(providerName))
}

// VerifyStoredSecrets authenticates every restored provider envelope without
// installing providers or making upstream network requests.
func (m *Manager) VerifyStoredSecrets(ctx context.Context) (int64, error) {
	if m == nil || m.db == nil {
		return 0, errors.New("provider database is unavailable")
	}
	rows, err := m.db.Query(ctx, `SELECT name,client_secret FROM oauth_providers ORDER BY name`)
	if err != nil {
		return 0, fmt.Errorf("querying provider envelopes: %w", err)
	}
	defer rows.Close()

	var verified int64
	for rows.Next() {
		var name, ciphertext string
		if err := rows.Scan(&name, &ciphertext); err != nil {
			return 0, fmt.Errorf("scanning provider envelope: %w", err)
		}
		if _, err := m.decryptSecret(name, ciphertext); err != nil {
			return 0, fmt.Errorf("verifying provider %q envelope: %w", name, err)
		}
		verified++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterating provider envelopes: %w", err)
	}
	return verified, nil
}

func (m *Manager) decryptSecret(providerName, ciphertext string) (string, error) {
	plaintext, err := crypto.DecryptEnvelope(m.masterKeys, providerSecretPurpose, ciphertext, []byte(providerName))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
