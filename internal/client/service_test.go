package client

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestBuildClientInitializesSecretMetadata(t *testing.T) {
	t.Parallel()
	rotatedAt := time.Date(2026, 7, 26, 8, 30, 0, 0, time.UTC)
	service := &Service{
		generateSecret: func() (string, error) { return "confidential-secret-value", nil },
		clock:          func() time.Time { return rotatedAt },
	}

	confidential, secret, err := service.buildClient(models.CreateClientRequest{
		Name: "Confidential", RedirectURIs: []string{"https://client.example/callback"},
		Grants: []string{models.GrantAuthorizationCode},
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret != "confidential-secret-value" || confidential.SecretHash == nil {
		t.Fatal("confidential client secret was not generated and hashed")
	}
	if confidential.SecretVersion != 1 || confidential.SecretRotatedAt == nil || !confidential.SecretRotatedAt.Equal(rotatedAt) {
		t.Fatalf("unexpected confidential secret metadata: version=%d rotated_at=%v", confidential.SecretVersion, confidential.SecretRotatedAt)
	}
	if confidential.SecretHint == nil || *confidential.SecretHint != "-value" {
		t.Fatalf("secret hint = %v, want %q", confidential.SecretHint, "-value")
	}

	public, secret, err := service.buildClient(models.CreateClientRequest{
		Name: "Public", RedirectURIs: []string{"https://client.example/callback"},
		Grants: []string{models.GrantAuthorizationCode}, IsPublic: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" || public.SecretHash != nil || public.SecretHint != nil || public.SecretVersion != 0 || public.SecretRotatedAt != nil {
		t.Fatalf("public client unexpectedly has secret metadata: %#v", public)
	}
}

func TestNormalizeOwnerID(t *testing.T) {
	t.Parallel()
	canonical := "2f1c9f8d-8fb2-4741-8a7c-3e9ce813e2ee"
	nonCanonical := "  {2F1C9F8D-8FB2-4741-8A7C-3E9CE813E2EE}  "
	normalized, err := normalizeOwnerID(&nonCanonical)
	if err != nil {
		t.Fatal(err)
	}
	if normalized == nil || *normalized != canonical {
		t.Fatalf("normalized owner = %v, want %q", normalized, canonical)
	}
	if normalized, err := normalizeOwnerID(nil); err != nil || normalized != nil {
		t.Fatalf("nil owner normalized to %v with error %v", normalized, err)
	}
	for _, value := range []string{"", "   ", "not-a-uuid"} {
		value := value
		if _, err := normalizeOwnerID(&value); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("normalizeOwnerID(%q) error = %v", value, err)
		}
	}
}

func TestUnauditedCreateRejectsOwnerAssignment(t *testing.T) {
	t.Parallel()
	ownerID := "2f1c9f8d-8fb2-4741-8a7c-3e9ce813e2ee"
	service := &Service{}
	if _, err := service.Create(context.Background(), models.CreateClientRequest{OwnerID: &ownerID}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("Create owner assignment error = %v", err)
	}
}

func TestBuildClientValidatesAccessPolicy(t *testing.T) {
	service := NewService(nil)
	base := models.CreateClientRequest{Name: "App", RedirectURIs: []string{"https://app.example/cb"}, Grants: []string{models.GrantAuthorizationCode}}

	valid := base
	valid.AccessPolicy = models.ClientAccessAllowlist
	client, _, err := service.buildClient(valid)
	if err != nil {
		t.Fatal(err)
	}
	if client.AccessPolicy != models.ClientAccessAllowlist {
		t.Fatalf("access policy = %q", client.AccessPolicy)
	}

	defaulted, _, err := service.buildClient(base)
	if err != nil {
		t.Fatal(err)
	}
	if defaulted.AccessPolicy != models.ClientAccessOpen {
		t.Fatalf("default access policy = %q", defaulted.AccessPolicy)
	}

	invalid := base
	invalid.AccessPolicy = "vip_only"
	if _, _, err := service.buildClient(invalid); err == nil {
		t.Fatal("invalid access policy was accepted")
	}
}

func TestOAuthPolicyConstrainsNewClientsWithoutBreakingExistingEdits(t *testing.T) {
	policy := settings.DefaultOAuthPolicy()
	policy.PublicClientsEnabled = false
	policy.AllowedGrantTypes = []string{models.GrantAuthorizationCode}
	policy.AllowedScopes = []string{"openid"}
	policy.MaxRedirectURIs = 1
	policy.MaxPostLogoutRedirectURIs = 0

	service := NewService(nil)
	service.SetOAuthPolicySource(func() settings.Versioned[settings.OAuthPolicy] {
		return settings.Versioned[settings.OAuthPolicy]{Revision: 3, Value: policy}
	})
	base := models.CreateClientRequest{
		Name: "App", RedirectURIs: []string{"https://app.example/callback"},
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"openid"},
	}
	if _, _, err := service.buildClient(base); err != nil {
		t.Fatalf("policy-compliant client rejected: %v", err)
	}
	public := base
	public.IsPublic = true
	if _, _, err := service.buildClient(public); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("public client error = %v", err)
	}
	tooMany := base
	tooMany.RedirectURIs = append(tooMany.RedirectURIs, "https://app.example/other")
	if _, _, err := service.buildClient(tooMany); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("redirect limit error = %v", err)
	}
	forbiddenScope := base
	forbiddenScope.Scopes = []string{"openid", "email"}
	if _, _, err := service.buildClient(forbiddenScope); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("scope policy error = %v", err)
	}

	previous := &models.OAuthClient{
		RedirectURIs: []string{"https://app.example/one", "https://app.example/two"},
		Grants:       []string{models.GrantAuthorizationCode, models.GrantRefreshToken},
		Scopes:       []string{"openid", "email"},
	}
	replacement := *previous
	replacement.RedirectURIs = []string{"https://app.example/new-one", "https://app.example/new-two"}
	if err := validateUpdatedClientPolicy(previous, &replacement, models.UpdateClientRequest{RedirectURIs: replacement.RedirectURIs}, policy); err != nil {
		t.Fatalf("same-size legacy URI replacement rejected: %v", err)
	}
	expanded := replacement
	expanded.RedirectURIs = append(expanded.RedirectURIs, "https://app.example/three")
	if err := validateUpdatedClientPolicy(previous, &expanded, models.UpdateClientRequest{RedirectURIs: expanded.RedirectURIs}, policy); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("legacy URI expansion error = %v", err)
	}
	if err := validateUpdatedClientPolicy(previous, &replacement, models.UpdateClientRequest{Grants: replacement.Grants, Scopes: replacement.Scopes}, policy); err != nil {
		t.Fatalf("unchanged legacy grant/scope rejected: %v", err)
	}
}

func TestClientCredentialsDoesNotRequireRedirectURI(t *testing.T) {
	service := NewService(nil)
	machine, _, err := service.buildClient(models.CreateClientRequest{
		Name: "Machine", Grants: []string{models.GrantClientCredentials}, Scopes: []string{"openid"},
	})
	if err != nil {
		t.Fatalf("client_credentials without redirect URI rejected: %v", err)
	}
	if machine.RedirectURIs == nil || len(machine.RedirectURIs) != 0 {
		t.Fatalf("machine redirect URIs = %#v, want non-nil empty slice", machine.RedirectURIs)
	}
	if _, _, err := service.buildClient(models.CreateClientRequest{
		Name: "Browser", Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"openid"},
	}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("authorization_code without redirect URI error = %v", err)
	}
}

func TestOfflineAccessRequiresRefreshTokenForNewClientsButLegacyStateCanBeRepaired(t *testing.T) {
	service := NewService(nil)
	request := models.CreateClientRequest{
		Name: "Offline", RedirectURIs: []string{"https://client.example/callback"},
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"openid", "offline_access"},
	}
	if _, _, err := service.buildClient(request); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("offline_access without refresh_token error = %v", err)
	}

	policy := settings.DefaultOAuthPolicy()
	legacy := &models.OAuthClient{
		RedirectURIs: request.RedirectURIs, Grants: request.Grants, Scopes: request.Scopes,
	}
	unchanged := *legacy
	if err := validateUpdatedClientPolicy(legacy, &unchanged, models.UpdateClientRequest{}, policy); err != nil {
		t.Fatalf("unchanged legacy offline_access state rejected: %v", err)
	}
	repaired := unchanged
	repaired.Scopes = []string{"openid"}
	if err := validateUpdatedClientPolicy(legacy, &repaired, models.UpdateClientRequest{Scopes: repaired.Scopes}, policy); err != nil {
		t.Fatalf("legacy offline_access repair rejected: %v", err)
	}
}

func TestSelfServiceCreationCanBeDisabled(t *testing.T) {
	policy := settings.DefaultOAuthPolicy()
	policy.SelfServiceClientCreationEnabled = false
	service := NewService(nil)
	service.SetOAuthPolicySource(func() settings.Versioned[settings.OAuthPolicy] {
		return settings.Versioned[settings.OAuthPolicy]{Value: policy}
	})
	_, err := service.CreateForOwner(context.Background(), "2f1c9f8d-8fb2-4741-8a7c-3e9ce813e2ee", models.CreateClientRequest{})
	if !errors.Is(err, ErrSelfServiceDisabled) {
		t.Fatalf("disabled self-service error = %v", err)
	}
}

func TestSelfServiceCannotAssignAdministratorOnlyScopesOrClaims(t *testing.T) {
	policy := settings.DefaultOAuthPolicy()
	policy.AllowedScopes = append(policy.AllowedScopes, "tenant.read", "admin.role")
	policy.ScopeDefinitions["tenant.read"] = settings.OAuthScopeDefinition{
		DisplayName: "读取租户", Description: "读取当前用户可以访问的租户信息。",
		Claims: []string{"preferred_username", "role"}, AssignmentPolicy: settings.OAuthAssignmentSelfService, RiskLevel: settings.OAuthRiskPersonalData,
	}
	policy.ScopeDefinitions["admin.role"] = settings.OAuthScopeDefinition{
		DisplayName: "读取账户角色", Description: "读取用户在 Nyauth 中的账户角色。",
		Claims: []string{"role"}, AssignmentPolicy: settings.OAuthAssignmentAdminOnly, RiskLevel: settings.OAuthRiskSensitive,
	}
	normalized, err := settings.NormalizeOAuthPolicyUpdate(policy)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(nil)
	base := models.CreateClientRequest{
		Name: "Tenant App", RedirectURIs: []string{"https://app.example/callback"},
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"openid", "tenant.read"},
	}
	created, _, err := service.buildClientForActor(base, false, settings.Versioned[settings.OAuthPolicy]{Value: normalized})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(created.AllowedClaims, []string{"sub", "preferred_username"}) {
		t.Fatalf("self-service default claims = %#v", created.AllowedClaims)
	}
	withRole := base
	withRole.AllowedClaims = []string{"sub", "preferred_username", "role"}
	if _, _, err := service.buildClientForActor(withRole, false, settings.Versioned[settings.OAuthPolicy]{Value: normalized}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("self-service role assignment error = %v", err)
	}
	adminScope := base
	adminScope.Scopes = []string{"openid", "admin.role"}
	if _, _, err := service.buildClientForActor(adminScope, false, settings.Versioned[settings.OAuthPolicy]{Value: normalized}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("self-service admin scope error = %v", err)
	}
	admin, _, err := service.buildClientForActor(adminScope, true, settings.Versioned[settings.OAuthPolicy]{Value: normalized})
	if err != nil || !slices.Equal(admin.AllowedClaims, []string{"sub", "role"}) {
		t.Fatalf("administrator assignment = %#v, %v", admin, err)
	}
}

func TestOptionalScopesMustBeAValidAuthorizationCodeSubset(t *testing.T) {
	t.Parallel()
	service := NewService(nil)
	base := models.CreateClientRequest{
		Name: "Consent App", RedirectURIs: []string{"https://app.example/callback"},
		Grants: []string{models.GrantAuthorizationCode, models.GrantRefreshToken},
		Scopes: []string{"openid", "profile", "email", "offline_access"},
	}
	valid := base
	valid.OptionalScopes = []string{"profile", "offline_access"}
	created, _, err := service.buildClient(valid)
	if err != nil {
		t.Fatalf("valid optional scopes rejected: %v", err)
	}
	if len(created.OptionalScopes) != 2 || created.OptionalScopes[0] != "profile" || created.OptionalScopes[1] != "offline_access" {
		t.Fatalf("stored optional scopes = %#v", created.OptionalScopes)
	}

	tests := []struct {
		name   string
		mutate func(*models.CreateClientRequest)
	}{
		{name: "openid cannot be optional", mutate: func(req *models.CreateClientRequest) { req.OptionalScopes = []string{"openid"} }},
		{name: "scope must be allowed", mutate: func(req *models.CreateClientRequest) { req.OptionalScopes = []string{"groups"} }},
		{name: "duplicates are rejected", mutate: func(req *models.CreateClientRequest) { req.OptionalScopes = []string{"profile", "profile"} }},
		{name: "at least one scope remains required", mutate: func(req *models.CreateClientRequest) {
			req.Scopes = []string{"profile"}
			req.OptionalScopes = []string{"profile"}
		}},
		{name: "authorization code is required", mutate: func(req *models.CreateClientRequest) {
			req.RedirectURIs = nil
			req.Grants = []string{models.GrantClientCredentials}
			req.Scopes = []string{"profile", "service.read"}
			req.OptionalScopes = []string{"profile"}
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			request := base
			testCase.mutate(&request)
			if _, _, err := service.buildClient(request); !errors.Is(err, ErrInvalidClient) {
				t.Fatalf("invalid optional scopes error = %v", err)
			}
		})
	}
}
