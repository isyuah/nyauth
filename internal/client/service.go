package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

var (
	ErrInvalidClient       = errors.New("invalid OAuth client")
	ErrPublicClientSecret  = errors.New("public OAuth clients do not have a client secret")
	ErrClientNotOwned      = errors.New("OAuth client is not owned by current user")
	ErrOAuthPolicyChanged  = errors.New("OAuth client policy changed")
	ErrSelfServiceDisabled = errors.New("self-service client creation is disabled")
)

type Service struct {
	store          *Store
	generateSecret func() (string, error)
	clock          func() time.Time
	policySource   func() settings.Versioned[settings.OAuthPolicy]
}

func NewService(store *Store) *Service {
	return &Service{store: store, generateSecret: crypto.GenerateClientSecret, clock: time.Now}
}

func (s *Service) SetOAuthPolicySource(source func() settings.Versioned[settings.OAuthPolicy]) {
	s.policySource = source
}

func (s *Service) oauthPolicySnapshot() settings.Versioned[settings.OAuthPolicy] {
	if s.policySource != nil {
		return s.policySource()
	}
	return settings.Versioned[settings.OAuthPolicy]{Value: settings.DefaultOAuthPolicy()}
}

func validateRedirectURI(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%w: invalid redirect URI", ErrInvalidClient)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("%w: redirect URI must use HTTPS except for loopback development clients", ErrInvalidClient)
}
func validateRequest(req models.CreateClientRequest) error {
	if strings.TrimSpace(req.Name) == "" || len(req.Name) > 128 {
		return fmt.Errorf("%w: client name is required", ErrInvalidClient)
	}
	if len(req.Grants) == 0 {
		return fmt.Errorf("%w: at least one grant is required", ErrInvalidClient)
	}
	seen := map[string]bool{}
	for _, grant := range req.Grants {
		if seen[grant] {
			return fmt.Errorf("%w: duplicate grant", ErrInvalidClient)
		}
		seen[grant] = true
		switch grant {
		case models.GrantAuthorizationCode, models.GrantClientCredentials, models.GrantRefreshToken:
		default:
			return fmt.Errorf("%w: unsupported grant %q", ErrInvalidClient, grant)
		}
	}
	if req.IsPublic && seen[models.GrantClientCredentials] {
		return fmt.Errorf("%w: public clients cannot use client_credentials", ErrInvalidClient)
	}
	if seen[models.GrantRefreshToken] && !seen[models.GrantAuthorizationCode] {
		return fmt.Errorf("%w: refresh_token requires authorization_code", ErrInvalidClient)
	}
	if seen[models.GrantAuthorizationCode] && len(req.RedirectURIs) == 0 {
		return fmt.Errorf("%w: authorization_code requires at least one redirect URI", ErrInvalidClient)
	}
	for _, value := range append(append([]string{}, req.RedirectURIs...), req.PostLogoutRedirectURIs...) {
		if err := validateRedirectURI(value); err != nil {
			return err
		}
	}
	scopeSeen := make(map[string]bool, len(req.Scopes))
	for _, scope := range req.Scopes {
		if !models.ValidOAuthScope(scope) {
			return fmt.Errorf("%w: invalid scope %q", ErrInvalidClient, scope)
		}
		if scopeSeen[scope] {
			return fmt.Errorf("%w: duplicate scope %q", ErrInvalidClient, scope)
		}
		scopeSeen[scope] = true
	}
	if req.AccessPolicy != "" && !models.ValidClientAccessPolicy(req.AccessPolicy) {
		return fmt.Errorf("%w: unsupported access policy %q", ErrInvalidClient, req.AccessPolicy)
	}
	return nil
}
func applyRequestDefaults(req *models.CreateClientRequest, policy settings.OAuthPolicy) {
	if req.RedirectURIs == nil {
		req.RedirectURIs = []string{}
	}
	if req.Grants == nil {
		if policy.AllowsGrant(models.GrantAuthorizationCode) {
			req.Grants = []string{models.GrantAuthorizationCode}
		} else {
			req.Grants = []string{policy.AllowedGrantTypes[0]}
		}
	}
	if req.Scopes == nil {
		for _, scope := range []string{"openid", "profile", "email"} {
			if policy.AllowsScope(scope) {
				req.Scopes = append(req.Scopes, scope)
			}
		}
	}
	if req.PostLogoutRedirectURIs == nil {
		req.PostLogoutRedirectURIs = []string{}
	}
}

func validateNewClientPolicy(req models.CreateClientRequest, policy settings.OAuthPolicy) error {
	if slices.Contains(req.Scopes, "offline_access") && !slices.Contains(req.Grants, models.GrantRefreshToken) {
		return fmt.Errorf("%w: offline_access requires refresh_token", ErrInvalidClient)
	}
	if req.IsPublic && !policy.PublicClientsEnabled {
		return fmt.Errorf("%w: public client creation is disabled by OAuth policy", ErrInvalidClient)
	}
	if len(req.RedirectURIs) > policy.MaxRedirectURIs {
		return fmt.Errorf("%w: at most %d redirect URIs are allowed", ErrInvalidClient, policy.MaxRedirectURIs)
	}
	if len(req.PostLogoutRedirectURIs) > policy.MaxPostLogoutRedirectURIs {
		return fmt.Errorf("%w: at most %d post-logout redirect URIs are allowed", ErrInvalidClient, policy.MaxPostLogoutRedirectURIs)
	}
	for _, grant := range req.Grants {
		if !policy.AllowsGrant(grant) {
			return fmt.Errorf("%w: grant %q is disabled by OAuth policy", ErrInvalidClient, grant)
		}
	}
	for _, scope := range req.Scopes {
		if !policy.AllowsScope(scope) {
			return fmt.Errorf("%w: scope %q is disabled by OAuth policy", ErrInvalidClient, scope)
		}
	}
	return nil
}

func validateUpdatedClientPolicy(previous, next *models.OAuthClient, request models.UpdateClientRequest, policy settings.OAuthPolicy) error {
	previousHasInvalidOfflineAccess := slices.Contains(previous.Scopes, "offline_access") && !slices.Contains(previous.Grants, models.GrantRefreshToken)
	nextHasInvalidOfflineAccess := slices.Contains(next.Scopes, "offline_access") && !slices.Contains(next.Grants, models.GrantRefreshToken)
	if nextHasInvalidOfflineAccess && !previousHasInvalidOfflineAccess {
		return fmt.Errorf("%w: offline_access requires refresh_token", ErrInvalidClient)
	}
	if request.RedirectURIs != nil && len(next.RedirectURIs) > policy.MaxRedirectURIs && len(next.RedirectURIs) > len(previous.RedirectURIs) {
		return fmt.Errorf("%w: at most %d redirect URIs are allowed", ErrInvalidClient, policy.MaxRedirectURIs)
	}
	if request.PostLogoutRedirectURIs != nil && len(next.PostLogoutRedirectURIs) > policy.MaxPostLogoutRedirectURIs && len(next.PostLogoutRedirectURIs) > len(previous.PostLogoutRedirectURIs) {
		return fmt.Errorf("%w: at most %d post-logout redirect URIs are allowed", ErrInvalidClient, policy.MaxPostLogoutRedirectURIs)
	}
	if request.Grants != nil {
		for _, grant := range next.Grants {
			if !slices.Contains(previous.Grants, grant) && !policy.AllowsGrant(grant) {
				return fmt.Errorf("%w: grant %q is disabled by OAuth policy", ErrInvalidClient, grant)
			}
		}
	}
	if request.Scopes != nil {
		for _, scope := range next.Scopes {
			if !slices.Contains(previous.Scopes, scope) && !policy.AllowsScope(scope) {
				return fmt.Errorf("%w: scope %q is disabled by OAuth policy", ErrInvalidClient, scope)
			}
		}
	}
	return nil
}

func (s *Service) buildClient(req models.CreateClientRequest, snapshots ...settings.Versioned[settings.OAuthPolicy]) (*models.OAuthClient, string, error) {
	policySnapshot := s.oauthPolicySnapshot()
	if len(snapshots) > 0 {
		policySnapshot = snapshots[0]
	}
	applyRequestDefaults(&req, policySnapshot.Value)
	if err := validateRequest(req); err != nil {
		return nil, "", err
	}
	if err := validateNewClientPolicy(req, policySnapshot.Value); err != nil {
		return nil, "", err
	}
	id, err := crypto.GenerateClientID()
	if err != nil {
		return nil, "", fmt.Errorf("generating client ID: %w", err)
	}
	secret := ""
	var secretHash *string
	if !req.IsPublic {
		secret, err = s.generateSecret()
		if err != nil {
			return nil, "", fmt.Errorf("generating client secret: %w", err)
		}
		hash := crypto.HashClientSecret(secret)
		secretHash = &hash
	}
	if req.AccessPolicy == "" {
		req.AccessPolicy = models.ClientAccessOpen
	}
	c := &models.OAuthClient{ID: id, SecretHash: secretHash, Name: strings.TrimSpace(req.Name), RedirectURIs: req.RedirectURIs, PostLogoutRedirectURIs: req.PostLogoutRedirectURIs, Grants: req.Grants, Scopes: req.Scopes, IsPublic: req.IsPublic, AccessPolicy: req.AccessPolicy, Metadata: req.Metadata}
	if !req.IsPublic {
		hint := clientSecretHint(secret)
		rotatedAt := s.clock().UTC()
		c.SecretHint = &hint
		c.SecretVersion = 1
		c.SecretRotatedAt = &rotatedAt
	}
	if c.Metadata == nil {
		c.Metadata = map[string]string{}
	}
	return c, secret, nil
}
func response(c *models.OAuthClient, secret string) *models.CreateClientResponse {
	return &models.CreateClientResponse{OAuthClient: *c, Secret: secret}
}
func (s *Service) Create(ctx context.Context, req models.CreateClientRequest) (*models.CreateClientResponse, error) {
	if req.OwnerID != nil {
		return nil, fmt.Errorf("%w: owner_id requires the audited admin creation path", ErrInvalidClient)
	}
	policy := s.oauthPolicySnapshot()
	c, secret, err := s.buildClient(req, policy)
	if err != nil {
		return nil, err
	}
	if err := s.store.CreateWithOAuthPolicy(ctx, c, policy); err != nil {
		return nil, err
	}
	return response(c, secret), nil
}
func (s *Service) CreateAdmin(ctx context.Context, req models.CreateClientRequest, mutation audit.MutationAudit) (*models.CreateClientResponse, error) {
	if err := mutation.ValidateEvent(models.AuditClientCreated); err != nil {
		return nil, fmt.Errorf("invalid client creation audit context: %w", err)
	}
	ownerID, err := normalizeOwnerID(req.OwnerID)
	if err != nil {
		return nil, err
	}
	policy := s.oauthPolicySnapshot()
	c, secret, err := s.buildClient(req, policy)
	if err != nil {
		return nil, err
	}
	if err := s.store.CreateWithAuditAndOAuthPolicy(ctx, c, ownerID, mutation, policy); err != nil {
		return nil, err
	}
	return response(c, secret), nil
}
func (s *Service) CreateForOwner(ctx context.Context, ownerID string, req models.CreateClientRequest) (*models.CreateClientResponse, error) {
	if req.OwnerID != nil {
		return nil, fmt.Errorf("%w: owner_id is managed by the self-service route", ErrInvalidClient)
	}
	normalizedOwnerID, err := normalizeOwnerID(&ownerID)
	if err != nil {
		return nil, err
	}
	policy := s.oauthPolicySnapshot()
	if !policy.Value.SelfServiceClientCreationEnabled {
		return nil, ErrSelfServiceDisabled
	}
	c, secret, err := s.buildClient(req, policy)
	if err != nil {
		return nil, err
	}
	if err := s.store.CreateForOwnerWithOAuthPolicy(ctx, c, *normalizedOwnerID, policy); err != nil {
		return nil, err
	}
	return response(c, secret), nil
}
func (s *Service) GetByID(ctx context.Context, id string) (*models.OAuthClient, error) {
	return s.store.GetByID(ctx, id)
}
func (s *Service) Update(ctx context.Context, id string, req models.UpdateClientRequest, mutation audit.MutationAudit) (*models.OAuthClient, error) {
	if err := mutation.ValidateEvent(models.AuditClientUpdated); err != nil {
		return nil, fmt.Errorf("invalid client update audit context: %w", err)
	}
	policy := s.oauthPolicySnapshot()
	return s.store.UpdateRequestWithOAuthPolicy(ctx, id, req, mutation, policy)
}

func applyClientUpdate(c *models.OAuthClient, req models.UpdateClientRequest) error {
	if req.IsPublic != nil && *req.IsPublic != c.IsPublic {
		return fmt.Errorf("%w: client type cannot be changed", ErrInvalidClient)
	}
	if req.Name != nil {
		c.Name = strings.TrimSpace(*req.Name)
	}
	if req.RedirectURIs != nil {
		c.RedirectURIs = req.RedirectURIs
	}
	if req.PostLogoutRedirectURIs != nil {
		c.PostLogoutRedirectURIs = req.PostLogoutRedirectURIs
	}
	if req.Grants != nil {
		c.Grants = req.Grants
	}
	if req.Scopes != nil {
		c.Scopes = req.Scopes
	}
	if req.Metadata != nil {
		c.Metadata = req.Metadata
	}
	if req.AccessPolicy != nil {
		c.AccessPolicy = *req.AccessPolicy
	}
	if c.AccessPolicy == "" {
		c.AccessPolicy = models.ClientAccessOpen
	}
	check := models.CreateClientRequest{Name: c.Name, RedirectURIs: c.RedirectURIs, PostLogoutRedirectURIs: c.PostLogoutRedirectURIs, Grants: c.Grants, Scopes: c.Scopes, IsPublic: c.IsPublic, AccessPolicy: c.AccessPolicy, Metadata: c.Metadata}
	if err := validateRequest(check); err != nil {
		return err
	}
	return nil
}
func (s *Service) UpdateOwner(ctx context.Context, id string, req models.UpdateClientOwnerRequest, mutation audit.MutationAudit) (*models.OAuthClient, error) {
	if err := mutation.ValidateEvent(models.AuditClientOwnerChanged); err != nil {
		return nil, fmt.Errorf("invalid client owner audit context: %w", err)
	}
	ownerID, err := normalizeOwnerID(req.OwnerID)
	if err != nil {
		return nil, err
	}
	return s.store.UpdateOwner(ctx, id, ownerID, mutation)
}
func (s *Service) Delete(ctx context.Context, id string, mutation audit.MutationAudit) error {
	if err := mutation.ValidateEvent(models.AuditClientDeleted); err != nil {
		return fmt.Errorf("invalid client deletion audit context: %w", err)
	}
	return s.store.Delete(ctx, id, mutation)
}
func (s *Service) DeleteForOwner(ctx context.Context, id, ownerID string) error {
	return s.store.DeleteForOwner(ctx, id, ownerID)
}
func (s *Service) List(ctx context.Context, page, pageSize int) (*models.PaginatedResponse[models.OAuthClient], error) {
	return s.store.List(ctx, models.NewPagination(page, pageSize))
}
func (s *Service) AuthenticateClient(ctx context.Context, id, secret string) (*models.OAuthClient, error) {
	return s.store.AuthenticateClient(ctx, id, secret)
}
func (s *Service) ListByOwner(ctx context.Context, ownerID string, page, pageSize int) (*models.PaginatedResponse[models.OAuthClient], error) {
	return s.store.ListByOwner(ctx, ownerID, models.NewPagination(page, pageSize))
}
func (s *Service) CountByOwner(ctx context.Context, ownerID string) (int64, error) {
	return s.store.CountByOwner(ctx, ownerID)
}
func (s *Service) GetOwnerQuota(ctx context.Context, ownerID string) (*OwnerQuota, error) {
	normalizedOwnerID, err := normalizeOwnerID(&ownerID)
	if err != nil {
		return nil, err
	}
	return s.store.GetOwnerQuota(ctx, *normalizedOwnerID)
}
func (s *Service) UpdateOwnerQuota(ctx context.Context, ownerID string, override *int, mutation audit.MutationAudit) (*OwnerQuota, error) {
	normalizedOwnerID, err := normalizeOwnerID(&ownerID)
	if err != nil {
		return nil, err
	}
	return s.store.UpdateOwnerQuota(ctx, *normalizedOwnerID, override, mutation)
}
func (s *Service) RotateSecret(ctx context.Context, clientID string, mutation audit.MutationAudit) (*models.RotateClientSecretResponse, error) {
	if err := mutation.ValidateEvent(models.AuditClientSecretRotated); err != nil {
		return nil, fmt.Errorf("invalid client rotation audit context: %w", err)
	}
	registered, err := s.store.GetByID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if registered.IsPublic {
		return nil, ErrPublicClientSecret
	}
	return s.rotateSecret(ctx, clientID, "", false, mutation)
}
func (s *Service) RotateSecretForOwner(ctx context.Context, clientID, ownerID string) (*models.RotateClientSecretResponse, error) {
	registered, err := s.store.GetByID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if registered.OwnerID == nil || *registered.OwnerID != ownerID {
		return nil, ErrClientNotOwned
	}
	if registered.IsPublic {
		return nil, ErrPublicClientSecret
	}
	return s.rotateSecret(ctx, clientID, ownerID, true, audit.MutationAudit{})
}
func (s *Service) rotateSecret(ctx context.Context, clientID, ownerID string, owned bool, mutation audit.MutationAudit) (*models.RotateClientSecretResponse, error) {
	secret, err := s.generateSecret()
	if err != nil {
		return nil, fmt.Errorf("generating client secret: %w", err)
	}
	hint := clientSecretHint(secret)
	rotatedAt := s.clock().UTC()
	secretHash := crypto.HashClientSecret(secret)
	var version int64
	if owned {
		version, err = s.store.RotateSecretForOwner(ctx, clientID, ownerID, secretHash, hint, rotatedAt)
	} else {
		version, err = s.store.RotateSecret(ctx, clientID, secretHash, hint, rotatedAt, mutation)
	}
	if err != nil {
		return nil, err
	}
	return &models.RotateClientSecretResponse{
		ClientID: clientID, Secret: secret, SecretHint: hint,
		SecretVersion: version, SecretRotatedAt: rotatedAt,
	}, nil
}
func (s *Service) GetStore() *Store  { return s.store }
func IsInvalidClient(err error) bool { return errors.Is(err, ErrInvalidClient) }

func clientSecretHint(secret string) string {
	const length = 6
	if len(secret) <= length {
		return secret
	}
	return secret[len(secret)-length:]
}

func normalizeOwnerID(ownerID *string) (*string, error) {
	if ownerID == nil {
		return nil, nil
	}
	value := strings.TrimSpace(*ownerID)
	if value == "" {
		return nil, fmt.Errorf("%w: owner_id must be a UUID or null", ErrInvalidClient)
	}
	parsed, err := uuid.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("%w: owner_id must be a UUID or null", ErrInvalidClient)
	}
	canonical := parsed.String()
	return &canonical, nil
}

// ListAccessUsers returns the allowlisted users for a client.
func (s *Service) ListAccessUsers(ctx context.Context, id string) ([]models.ClientAccessUser, error) {
	return s.store.ListAccessUsers(ctx, id)
}

const maxAccessUsers = 500

// ReplaceAccessUsers validates and replaces a client's allowlist, returning
// the stored list.
func (s *Service) ReplaceAccessUsers(ctx context.Context, id string, req models.ReplaceClientAccessUsersRequest, mutation audit.MutationAudit) ([]models.ClientAccessUser, error) {
	if err := mutation.ValidateEvent(models.AuditClientAccessChanged); err != nil {
		return nil, fmt.Errorf("invalid client access audit context: %w", err)
	}
	if len(req.UserIDs) > maxAccessUsers {
		return nil, fmt.Errorf("%w: at most %d users may be allowlisted", ErrInvalidClient, maxAccessUsers)
	}
	seen := make(map[string]bool, len(req.UserIDs))
	userIDs := make([]string, 0, len(req.UserIDs))
	for _, raw := range req.UserIDs {
		parsed, err := uuid.Parse(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid user ID %q", ErrInvalidClient, raw)
		}
		value := parsed.String()
		if !seen[value] {
			seen[value] = true
			userIDs = append(userIDs, value)
		}
	}
	if err := s.store.ReplaceAccessUsers(ctx, id, userIDs, mutation); err != nil {
		return nil, err
	}
	return s.store.ListAccessUsers(ctx, id)
}
