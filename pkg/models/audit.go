package models

import (
	"time"

	"github.com/google/uuid"
)

// AuditLog represents an audit log entry.
type AuditLog struct {
	ID         uuid.UUID              `json:"id" db:"id"`
	Event      string                 `json:"event" db:"event"`
	ActorID    *uuid.UUID             `json:"actor_id,omitempty" db:"actor_id"`
	ActorName  *string                `json:"actor_name,omitempty" db:"actor_name"`
	TargetType *string                `json:"target_type,omitempty" db:"target_type"`
	TargetID   *string                `json:"target_id,omitempty" db:"target_id"`
	IPAddress  *string                `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent  *string                `json:"-" db:"user_agent"`
	Result     string                 `json:"result" db:"result"`
	RiskLevel  string                 `json:"risk_level" db:"risk_level"`
	Details    map[string]interface{} `json:"details,omitempty" db:"details"`
	CreatedAt  time.Time              `json:"created_at" db:"created_at"`
}

// Audit event types
const (
	AuditUserLogin              = "user.login"
	AuditUserLoginFailed        = "user.login_failed"
	AuditUserCreated            = "user.created"
	AuditUserUpdated            = "user.updated"
	AuditUserDeleted            = "user.deleted"
	AuditUserPasswordReset      = "user.password_reset"
	AuditUserSuspended          = "user.suspended"
	AuditUserActivated          = "user.activated"
	AuditUserRoleChanged        = "user.role_changed"
	AuditUserProfileUpdated     = "user.profile_updated"
	AuditUserLogout             = "user.logout"
	AuditUserSessionsRevoked    = "session.user_revoked"
	AuditIdentityBindStarted    = "identity.bind_started"
	AuditIdentityBound          = "identity.bound"
	AuditIdentityUnbound        = "identity.unbound"
	AuditUserPasswordChanged    = "user.password_changed"
	AuditUserPasswordSet        = "user.password_configured"
	AuditConsentAccepted        = "consent.accepted"
	AuditConsentDenied          = "consent.denied"
	AuditClientCreated          = "client.created"
	AuditClientUpdated          = "client.updated"
	AuditClientOwnerChanged     = "client.owner_changed"
	AuditClientDeleted          = "client.deleted"
	AuditClientSecretRotated    = "client.secret_rotated"
	AuditAuthorizationRevoked   = "authorization.revoked"
	AuditAuthorizeDenied        = "authorize.access_denied"
	AuditClientAccessChanged    = "client.access_users_changed"
	AuditUserRegistered         = "user.registered"
	AuditInviteCreated          = "invite.created"
	AuditInviteRevoked          = "invite.revoked"
	AuditInviteReserved         = "invite.reserved"
	AuditInviteConsumed         = "invite.consumed"
	AuditInviteReleased         = "invite.reservation_released"
	AuditRegistrationExpired    = "registration.expired"
	AuditSettingsUpdated        = "settings.updated"
	AuditMailSettingsSaved      = "mail.settings_saved"
	AuditMailSettingsTested     = "mail.settings_tested"
	AuditMailSettingsActivated  = "mail.settings_activated"
	AuditMailSettingsDisabled   = "mail.settings_disabled"
	AuditMailSettingsRolledBack = "mail.settings_rolled_back"
	AuditMailCircuitOpened      = "mail.circuit_opened"
	AuditMailCircuitRecovered   = "mail.circuit_recovered"
	AuditMFAEnrolled            = "mfa.enrolled"
	AuditMFADisabled            = "mfa.disabled"
	AuditMFAChallengeFailed     = "mfa.challenge_failed"
	AuditRecoveryCodeUsed       = "recovery_code.used"
	AuditRecoveryCodesGenerated = "recovery_code.regenerated"
	AuditProviderCreated        = "provider.created"
	AuditProviderUpdated        = "provider.updated"
	AuditProviderTested         = "provider.tested"
	AuditProviderDeleted        = "provider.deleted"
	AuditTokenIssued            = "token.issued"
	AuditTokenGrantFailed       = "token.grant_failed"
	AuditRefreshTokenReuse      = "token.refresh_reuse"
	AuditTokenRevoked           = "token.revoked"
)
