package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

const providerSecretPurpose = "provider-client-secret"

var ErrProviderNotFound = errors.New("provider not found")

// Manager owns an immutable-at-read-time snapshot of enabled providers.
type Manager struct {
	mutationMu      sync.Mutex
	mu              sync.RWMutex
	providers       map[string]Provider
	staticProviders map[string]Provider
	db              *pgxpool.Pool
	masterKeys      map[string][]byte
	activeKeyID     string
	production      bool
}

// NewManager creates a provider manager. The optional production flag enables
// private-network egress blocking for generic discovery providers.
func NewManager(db *pgxpool.Pool, masterKey []byte, production ...bool) *Manager {
	isProduction := len(production) > 0 && production[0]
	keyCopy := append([]byte(nil), masterKey...)
	return &Manager{
		providers: make(map[string]Provider), staticProviders: make(map[string]Provider),
		db: db, masterKeys: map[string][]byte{"primary": keyCopy}, activeKeyID: "primary",
		production: isProduction,
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
		providers: make(map[string]Provider), staticProviders: make(map[string]Provider),
		db: db, masterKeys: keys, activeKeyID: activeKeyID, production: production,
	}, nil
}

// LoadStatic replaces the static provider snapshot.
func (m *Manager) LoadStatic(cfg map[string]config.ProviderConfig) {
	staticProviders := make(map[string]Provider, len(cfg))
	for name, providerConfig := range cfg {
		configured, err := m.providerFromConfig(name, providerConfig.Type, providerConfig.ClientID, providerConfig.ClientSecret,
			providerConfig.Scopes, providerConfig.DiscoveryURL, providerConfig.AuthorizationURL,
			providerConfig.TokenURL, providerConfig.UserinfoURL)
		if err != nil {
			fmt.Printf("warning: external provider %s was not loaded: %v\n", name, err)
			continue
		}
		staticProviders[name] = configured
	}
	m.mu.Lock()
	m.staticProviders = staticProviders
	m.providers = cloneProviders(staticProviders)
	m.mu.Unlock()
}

// LoadDynamic atomically replaces the runtime snapshot with static providers
// plus currently enabled database providers. Disabled and deleted providers are
// therefore removed immediately after a successful reload.
func (m *Manager) LoadDynamic(ctx context.Context) error {
	if m.db == nil {
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
	dynamicNames := make(map[string]struct{})
	for rows.Next() {
		var name, providerType, clientID, encryptedSecret string
		var enabled bool
		var scopes []string
		var discoveryURL, authorizationURL, tokenURL, userinfoURL *string
		if err := rows.Scan(&name, &providerType, &clientID, &encryptedSecret, &scopes, &discoveryURL, &authorizationURL, &tokenURL, &userinfoURL, &enabled); err != nil {
			return fmt.Errorf("scanning provider: %w", err)
		}
		dynamicNames[name] = struct{}{}
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
	next := cloneProviders(m.staticProviders)
	for name := range dynamicNames {
		delete(next, name)
	}
	for name, configured := range dynamicProviders {
		next[name] = configured
	}
	m.providers = next
	m.mu.Unlock()
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

func (m *Manager) CreateProvider(ctx context.Context, req models.CreateProviderRequest) (*models.ExternalProvider, error) {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	if m.db == nil {
		return nil, errors.New("provider database is unavailable")
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
		ClientSecret: encryptedSecret, Scopes: req.Scopes, Enabled: true,
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
	_, err = m.db.Exec(ctx, `
		INSERT INTO oauth_providers (name, type, client_id, client_secret, scopes, discovery_url, authorization_url, token_url, userinfo_url, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, configured.Name, configured.Type, configured.ClientID, configured.ClientSecret, configured.Scopes,
		configured.DiscoveryURL, configured.AuthorizationURL, configured.TokenURL, configured.UserinfoURL, configured.Enabled)
	if err != nil {
		return nil, fmt.Errorf("inserting provider: %w", err)
	}
	m.setDynamicProvider(req.Name, runtimeProvider, true)
	return configured, nil
}

// UpdateProvider validates the complete candidate before persisting it.
func (m *Manager) UpdateProvider(ctx context.Context, name string, req models.UpdateProviderRequest) (*models.ExternalProvider, error) {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	if m.db == nil {
		return nil, errors.New("provider database is unavailable")
	}
	var current models.ExternalProvider
	var encryptedSecret string
	err := m.db.QueryRow(ctx, `
		SELECT id,name,type,client_id,client_secret,scopes,discovery_url,authorization_url,
		       token_url,userinfo_url,enabled,metadata,created_at,updated_at
		FROM oauth_providers WHERE name=$1
	`, name).Scan(&current.ID, &current.Name, &current.Type, &current.ClientID, &encryptedSecret,
		&current.Scopes, &current.DiscoveryURL, &current.AuthorizationURL, &current.TokenURL,
		&current.UserinfoURL, &current.Enabled, &current.Metadata, &current.CreatedAt, &current.UpdatedAt)
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
	tag, err := m.db.Exec(ctx, `
		UPDATE oauth_providers SET client_id=$2,client_secret=$3,scopes=$4,discovery_url=$5,
		       authorization_url=$6,token_url=$7,userinfo_url=$8,enabled=$9,updated_at=NOW()
		WHERE name=$1
	`, name, current.ClientID, encryptedSecret, current.Scopes, current.DiscoveryURL,
		current.AuthorizationURL, current.TokenURL, current.UserinfoURL, current.Enabled)
	if err != nil {
		return nil, fmt.Errorf("updating provider: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrProviderNotFound
	}
	m.setDynamicProvider(name, runtimeProvider, current.Enabled)
	return &current, nil
}

func (m *Manager) DeleteProvider(ctx context.Context, name string) error {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	if m.db == nil {
		return errors.New("provider database is unavailable")
	}
	tag, err := m.db.Exec(ctx, `DELETE FROM oauth_providers WHERE name=$1`, name)
	if err != nil {
		return fmt.Errorf("deleting provider: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrProviderNotFound
	}
	m.restoreStaticProvider(name)
	return nil
}

// setDynamicProvider updates one runtime entry after its database mutation has
// committed. A disabled dynamic row deliberately shadows a same-name static
// provider, matching LoadDynamic semantics.
func (m *Manager) setDynamicProvider(name string, configured Provider, enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if enabled {
		m.providers[name] = configured
		return
	}
	delete(m.providers, name)
}

// restoreStaticProvider removes a deleted dynamic override and restores a
// same-name static provider when one exists.
func (m *Manager) restoreStaticProvider(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if configured, ok := m.staticProviders[name]; ok {
		m.providers[name] = configured
		return
	}
	delete(m.providers, name)
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

func (m *Manager) decryptSecret(providerName, ciphertext string) (string, error) {
	plaintext, err := crypto.DecryptEnvelope(m.masterKeys, providerSecretPurpose, ciphertext, []byte(providerName))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func cloneProviders(source map[string]Provider) map[string]Provider {
	cloned := make(map[string]Provider, len(source))
	for name, configured := range source {
		cloned[name] = configured
	}
	return cloned
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
