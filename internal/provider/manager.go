package provider

import (
	"context"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

// Manager manages external OAuth providers.
type Manager struct {
	mu        sync.RWMutex
	providers map[string]Provider
	db        *pgxpool.Pool
	encKey    []byte // encryption key for client secrets
}

// NewManager creates a new provider manager.
func NewManager(db *pgxpool.Pool, encKey []byte) *Manager {
	return &Manager{
		providers: make(map[string]Provider),
		db:        db,
		encKey:    encKey,
	}
}

// LoadStatic loads providers from the static configuration.
func (m *Manager) LoadStatic(cfg map[string]config.ProviderConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, pc := range cfg {
		switch pc.Type {
		case "github":
			m.providers[name] = NewGitHub(name, pc.ClientID, pc.ClientSecret, pc.Scopes)
		case "google":
			m.providers[name] = NewGoogle(name, pc.ClientID, pc.ClientSecret, pc.Scopes)
		case "generic":
			if pc.DiscoveryURL != "" {
				p, err := NewGenericOIDC(name, pc.ClientID, pc.ClientSecret, pc.Scopes, pc.DiscoveryURL)
				if err != nil {
					fmt.Printf("warning: failed to create generic provider %s: %v\n", name, err)
					continue
				}
				m.providers[name] = p
			} else if pc.AuthorizationURL != "" && pc.TokenURL != "" {
				m.providers[name] = NewGenericOIDCFromURLs(name, pc.ClientID, pc.ClientSecret, pc.Scopes, pc.AuthorizationURL, pc.TokenURL, pc.UserinfoURL)
			}
		default:
			fmt.Printf("warning: unsupported provider type %q for %s\n", pc.Type, name)
		}
	}
}

// LoadDynamic loads providers from the database and merges them.
func (m *Manager) LoadDynamic(ctx context.Context) error {
	if m.db == nil {
		return nil
	}

	rows, err := m.db.Query(ctx, `
		SELECT name, type, client_id, client_secret, scopes, discovery_url, authorization_url, token_url, userinfo_url
		FROM oauth_providers WHERE enabled = TRUE
	`)
	if err != nil {
		return fmt.Errorf("querying providers: %w", err)
	}
	defer rows.Close()

	m.mu.Lock()
	defer m.mu.Unlock()

	for rows.Next() {
		var name, ptype, clientID, encSecret string
		var scopes []string
		var discoveryURL, authURL, tokenURL, userinfoURL *string
		if err := rows.Scan(&name, &ptype, &clientID, &encSecret, &scopes, &discoveryURL, &authURL, &tokenURL, &userinfoURL); err != nil {
			return fmt.Errorf("scanning provider: %w", err)
		}

		// Decrypt the client secret
		secret, err := decryptSecret(encSecret, m.encKey)
		if err != nil {
			return fmt.Errorf("decrypting secret for %s: %w", name, err)
		}

		switch ptype {
		case "github":
			m.providers[name] = NewGitHub(name, clientID, secret, scopes)
		case "google":
			m.providers[name] = NewGoogle(name, clientID, secret, scopes)
		case "generic":
			if discoveryURL != nil && *discoveryURL != "" {
				p, err := NewGenericOIDC(name, clientID, secret, scopes, *discoveryURL)
				if err != nil {
					fmt.Printf("warning: failed to create generic provider %s: %v\n", name, err)
					continue
				}
				m.providers[name] = p
			} else if authURL != nil && tokenURL != nil {
				au, tu := *authURL, *tokenURL
				var uu string
				if userinfoURL != nil {
					uu = *userinfoURL
				}
				m.providers[name] = NewGenericOIDCFromURLs(name, clientID, secret, scopes, au, tu, uu)
			}
		}
	}
	return nil
}

// Get returns a provider by name.
func (m *Manager) Get(name string) (Provider, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.providers[name]
	return p, ok
}

// List returns all active provider names and types for the login page.
func (m *Manager) List() []ProviderInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var list []ProviderInfo
	for _, p := range m.providers {
		list = append(list, ProviderInfo{
			Name: p.Name(),
			Type: p.Type(),
		})
	}
	return list
}

// ProviderInfo is the public representation of a provider for the login page.
type ProviderInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// CreateProvider stores a new provider in the database.
func (m *Manager) CreateProvider(ctx context.Context, req models.CreateProviderRequest) (*models.ExternalProvider, error) {
	// Encrypt the client secret
	encSecret, err := encryptSecret(req.ClientSecret, m.encKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting secret: %w", err)
	}

	p := &models.ExternalProvider{
		Name:         req.Name,
		Type:         req.Type,
		ClientID:     req.ClientID,
		ClientSecret: encSecret,
		Scopes:       req.Scopes,
		Enabled:      true,
	}
	if req.DiscoveryURL != "" {
		p.DiscoveryURL = &req.DiscoveryURL
	}
	if req.AuthorizationURL != "" {
		p.AuthorizationURL = &req.AuthorizationURL
	}
	if req.TokenURL != "" {
		p.TokenURL = &req.TokenURL
	}
	if req.UserinfoURL != "" {
		p.UserinfoURL = &req.UserinfoURL
	}

	_, err = m.db.Exec(ctx, `
		INSERT INTO oauth_providers (name, type, client_id, client_secret, scopes, discovery_url, authorization_url, token_url, userinfo_url, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, p.Name, p.Type, p.ClientID, p.ClientSecret, p.Scopes, p.DiscoveryURL, p.AuthorizationURL, p.TokenURL, p.UserinfoURL, p.Enabled)
	if err != nil {
		return nil, fmt.Errorf("inserting provider: %w", err)
	}

	// Reload to make it available immediately
	m.LoadDynamic(ctx)

	return p, nil
}

func encryptSecret(plaintext string, key []byte) (string, error) {
	encrypted, err := crypto.Encrypt([]byte(plaintext), key)
	if err != nil {
		return "", err
	}
	return string(encrypted), nil
}

func decryptSecret(ciphertext string, key []byte) (string, error) {
	decrypted, err := crypto.Decrypt([]byte(ciphertext), key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}
