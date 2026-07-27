package mfa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	passkeyEnvelopePurpose  = "mfa.passkey.credential"
	passkeyUserHandleLength = 32
	passkeyCeremonyTTL      = 5 * time.Minute
)

var (
	ErrPasskeysUnavailable      = errors.New("Passkey service is unavailable")
	ErrPasskeysDisabled         = errors.New("Passkey enrollment is disabled")
	ErrPasskeyNotFound          = errors.New("Passkey not found")
	ErrPasskeyAlreadyRegistered = errors.New("Passkey is already registered")
	ErrInvalidPasskey           = errors.New("invalid Passkey response")
	ErrInvalidPasskeyName       = errors.New("invalid Passkey name")
	ErrLastAuthenticationMethod = errors.New("cannot remove the last authentication method")
)

type PasskeyConfig struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
}

type passkeyRuntime struct {
	webAuthn *gowebauthn.WebAuthn
	rpID     string
}

type PasskeyCredential struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	Transports     []string   `json:"transports"`
	AAGUID         string     `json:"aaguid,omitempty"`
	Attachment     string     `json:"attachment,omitempty"`
	BackupEligible bool       `json:"backup_eligible"`
	BackupState    bool       `json:"backup_state"`
	CloneWarning   bool       `json:"clone_warning"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
}

type PasskeyCreationOptions struct {
	PublicKey protocol.PublicKeyCredentialCreationOptions
	Session   []byte
	ExpiresAt time.Time
}

type PasskeyRequestOptions struct {
	PublicKey protocol.PublicKeyCredentialRequestOptions
	Mediation protocol.CredentialMediationRequirement
	Session   []byte
	ExpiresAt time.Time
}

type passkeyUser struct {
	id             uuid.UUID
	handle         []byte
	username       string
	displayName    string
	credentials    []gowebauthn.Credential
	rows           map[string]passkeyRow
	authVersion    int64
	sessionVersion int64
}

func (u *passkeyUser) WebAuthnID() []byte {
	return append([]byte(nil), u.handle...)
}

func (u *passkeyUser) WebAuthnName() string { return u.username }

func (u *passkeyUser) WebAuthnDisplayName() string {
	if strings.TrimSpace(u.displayName) != "" {
		return u.displayName
	}
	return u.username
}

func (u *passkeyUser) WebAuthnCredentials() []gowebauthn.Credential {
	return append([]gowebauthn.Credential(nil), u.credentials...)
}

func newPasskeyRuntime(config *PasskeyConfig) (*passkeyRuntime, error) {
	if config == nil {
		return nil, nil
	}
	rpID := strings.ToLower(strings.TrimSpace(config.RPID))
	displayName := strings.TrimSpace(config.RPDisplayName)
	if displayName == "" {
		displayName = "Nyauth"
	}
	origins := make([]string, 0, len(config.RPOrigins))
	for _, origin := range config.RPOrigins {
		if normalized := strings.TrimSpace(origin); normalized != "" {
			origins = append(origins, normalized)
		}
	}
	instance, err := gowebauthn.New(&gowebauthn.Config{
		RPID:                  rpID,
		RPDisplayName:         displayName,
		RPOrigins:             origins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		Timeouts: gowebauthn.TimeoutsConfig{
			Login:        gowebauthn.TimeoutConfig{Enforce: true, Timeout: passkeyCeremonyTTL, TimeoutUVD: passkeyCeremonyTTL},
			Registration: gowebauthn.TimeoutConfig{Enforce: true, Timeout: passkeyCeremonyTTL, TimeoutUVD: passkeyCeremonyTTL},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configuring Passkey WebAuthn: %w", err)
	}
	return &passkeyRuntime{webAuthn: instance, rpID: rpID}, nil
}

func ValidatePasskeyName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 64 {
		return "", ErrInvalidPasskeyName
	}
	return name, nil
}

func (s *Service) BeginPasskeyRegistration(ctx context.Context, current *models.User) (PasskeyCreationOptions, error) {
	if s.passkeys == nil {
		return PasskeyCreationOptions{}, ErrPasskeysUnavailable
	}
	user, err := s.loadOrCreatePasskeyUser(ctx, current)
	if err != nil {
		return PasskeyCreationOptions{}, err
	}
	creation, sessionData, err := s.passkeys.webAuthn.BeginMediatedRegistration(
		user,
		protocol.MediationRequired,
		gowebauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		gowebauthn.WithExclusions(gowebauthn.Credentials(user.credentials).CredentialDescriptors()),
		gowebauthn.WithExtensions(map[string]any{"credProps": true}),
		gowebauthn.WithPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{
			protocol.PublicKeyCredentialHintClientDevice,
			protocol.PublicKeyCredentialHintHybrid,
			protocol.PublicKeyCredentialHintSecurityKey,
		}),
	)
	if err != nil {
		return PasskeyCreationOptions{}, fmt.Errorf("starting Passkey registration: %w", err)
	}
	encoded, err := marshalPasskeySession(sessionData)
	if err != nil {
		return PasskeyCreationOptions{}, err
	}
	return PasskeyCreationOptions{
		PublicKey: creation.Response,
		Session:   encoded,
		ExpiresAt: sessionData.Expires.UTC(),
	}, nil
}

func (s *Service) BeginDiscoverablePasskeyLogin(conditional bool) (PasskeyRequestOptions, error) {
	if s.passkeys == nil {
		return PasskeyRequestOptions{}, ErrPasskeysUnavailable
	}
	mediation := protocol.MediationRequired
	if conditional {
		mediation = protocol.MediationConditional
	}
	assertion, sessionData, err := s.passkeys.webAuthn.BeginDiscoverableMediatedLogin(
		mediation,
		gowebauthn.WithUserVerification(protocol.VerificationRequired),
		gowebauthn.WithAssertionPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{
			protocol.PublicKeyCredentialHintClientDevice,
			protocol.PublicKeyCredentialHintHybrid,
			protocol.PublicKeyCredentialHintSecurityKey,
		}),
	)
	if err != nil {
		return PasskeyRequestOptions{}, fmt.Errorf("starting Passkey login: %w", err)
	}
	encoded, err := marshalPasskeySession(sessionData)
	if err != nil {
		return PasskeyRequestOptions{}, err
	}
	return PasskeyRequestOptions{
		PublicKey: assertion.Response,
		Mediation: mediation,
		Session:   encoded,
		ExpiresAt: sessionData.Expires.UTC(),
	}, nil
}

func (s *Service) BeginKnownPasskeyAuthentication(ctx context.Context, current *models.User) (PasskeyRequestOptions, error) {
	if s.passkeys == nil {
		return PasskeyRequestOptions{}, ErrPasskeysUnavailable
	}
	user, err := s.loadPasskeyUser(ctx, current)
	if err != nil {
		return PasskeyRequestOptions{}, err
	}
	if len(user.credentials) == 0 {
		return PasskeyRequestOptions{}, ErrPasskeyNotFound
	}
	assertion, sessionData, err := s.passkeys.webAuthn.BeginMediatedLogin(
		user,
		protocol.MediationRequired,
		gowebauthn.WithUserVerification(protocol.VerificationRequired),
		gowebauthn.WithAssertionPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{
			protocol.PublicKeyCredentialHintClientDevice,
			protocol.PublicKeyCredentialHintHybrid,
			protocol.PublicKeyCredentialHintSecurityKey,
		}),
	)
	if err != nil {
		return PasskeyRequestOptions{}, fmt.Errorf("starting Passkey authentication: %w", err)
	}
	encoded, err := marshalPasskeySession(sessionData)
	if err != nil {
		return PasskeyRequestOptions{}, err
	}
	return PasskeyRequestOptions{
		PublicKey: assertion.Response,
		Mediation: protocol.MediationRequired,
		Session:   encoded,
		ExpiresAt: sessionData.Expires.UTC(),
	}, nil
}

func marshalPasskeySession(value *gowebauthn.SessionData) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("Passkey session is required")
	}
	encoded, err := value.MarshalMsg(nil)
	if err != nil {
		return nil, fmt.Errorf("encoding Passkey session: %w", err)
	}
	return encoded, nil
}

func unmarshalPasskeySession(encoded []byte) (gowebauthn.SessionData, error) {
	var value gowebauthn.SessionData
	remainder, err := value.UnmarshalMsg(encoded)
	if err != nil {
		return gowebauthn.SessionData{}, fmt.Errorf("decoding Passkey session: %w", err)
	}
	if len(remainder) != 0 {
		return gowebauthn.SessionData{}, fmt.Errorf("decoding Passkey session: trailing data")
	}
	return value, nil
}
