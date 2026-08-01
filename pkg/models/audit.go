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
	AuditUserLogin                   = "user.login"
	AuditUserLoginFailed             = "user.login_failed"
	AuditUserCreated                 = "user.created"
	AuditUserUpdated                 = "user.updated"
	AuditUserDeleted                 = "user.deleted"
	AuditUserPasswordReset           = "user.password_reset"
	AuditUserSuspended               = "user.suspended"
	AuditUserActivated               = "user.activated"
	AuditUserRoleChanged             = "user.role_changed"
	AuditUserProfileUpdated          = "user.profile_updated"
	AuditUserLogout                  = "user.logout"
	AuditUserSessionsRevoked         = "session.user_revoked"
	AuditSessionRevoked              = "session.revoked"
	AuditSessionOthersRevoked        = "session.others_revoked"
	AuditTrustedDeviceCreated        = "trusted_device.created"
	AuditTrustedDeviceRevoked        = "trusted_device.revoked"
	AuditTrustedDeviceOthersRevoked  = "trusted_device.others_revoked"
	AuditUserReauthenticated         = "user.reauthenticated"
	AuditUserEmailChanged            = "user.email_changed"
	AuditUserEmailVerified           = "user.email_verified"
	AuditEmailChangeRequested        = "user.email_change_requested"
	AuditEmailVerifyRequested        = "user.email_verification_requested"
	AuditMutationUnclassified        = "http.mutation_unclassified"
	AuditIdentityBindStarted         = "identity.bind_started"
	AuditIdentityBound               = "identity.bound"
	AuditIdentityUnbound             = "identity.unbound"
	AuditUserPasswordChanged         = "user.password_changed"
	AuditUserPasswordSet             = "user.password_configured"
	AuditConsentAccepted             = "consent.accepted"
	AuditConsentDenied               = "consent.denied"
	AuditClientCreated               = "client.created"
	AuditClientUpdated               = "client.updated"
	AuditClientOwnerChanged          = "client.owner_changed"
	AuditClientDeleted               = "client.deleted"
	AuditClientSecretRotated         = "client.secret_rotated"
	AuditClientPublisherVerified     = "client.publisher_verified"
	AuditClientPublisherRevoked      = "client.publisher_verification_revoked"
	AuditAuthorizationRevoked        = "authorization.revoked"
	AuditAuthorizeDenied             = "authorize.access_denied"
	AuditClientAccessChanged         = "client.access_users_changed"
	AuditUserClientQuotaUpdated      = "user.client_quota_updated"
	AuditUserRegistered              = "user.registered"
	AuditInviteCreated               = "invite.created"
	AuditInviteRevoked               = "invite.revoked"
	AuditInviteReserved              = "invite.reserved"
	AuditInviteConsumed              = "invite.consumed"
	AuditInviteReleased              = "invite.reservation_released"
	AuditRegistrationExpired         = "registration.expired"
	AuditSettingsUpdated             = "settings.updated"
	AuditMailSettingsSaved           = "mail.settings_saved"
	AuditMailSettingsTested          = "mail.settings_tested"
	AuditMailSettingsActivated       = "mail.settings_activated"
	AuditMailSettingsDisabled        = "mail.settings_disabled"
	AuditMailSettingsRolledBack      = "mail.settings_rolled_back"
	AuditMailTemplateTested          = "mail.template_tested"
	AuditMailCircuitOpened           = "mail.circuit_opened"
	AuditMailCircuitRecovered        = "mail.circuit_recovered"
	AuditTelemetrySettingsSaved      = "telemetry.settings_saved"
	AuditTelemetrySettingsTested     = "telemetry.settings_tested"
	AuditTelemetrySettingsActivated  = "telemetry.settings_activated"
	AuditTelemetrySettingsDisabled   = "telemetry.settings_disabled"
	AuditTelemetrySettingsRolledBack = "telemetry.settings_rolled_back"
	AuditMFAEnrolled                 = "mfa.enrolled"
	AuditMFADisabled                 = "mfa.disabled"
	AuditMFAChallengeFailed          = "mfa.challenge_failed"
	AuditMFARecoveryReset            = "mfa.recovery_reset"
	AuditRecoveryCodeUsed            = "recovery_code.used"
	AuditRecoveryCodesGenerated      = "recovery_code.regenerated"
	AuditPasskeyRegistered           = "passkey.registered"
	AuditPasskeyRenamed              = "passkey.renamed"
	AuditPasskeyRemoved              = "passkey.removed"
	AuditPasskeyLogin                = "passkey.login"
	AuditProviderCreated             = "provider.created"
	AuditProviderUpdated             = "provider.updated"
	AuditProviderTested              = "provider.tested"
	AuditProviderDeleted             = "provider.deleted"
	AuditUserAvatarUpdated           = "user.avatar_updated"
	AuditUserAvatarRemoved           = "user.avatar_removed"
	AuditAdminUserAvatarUpdated      = "admin.user_avatar_updated"
	AuditAdminUserAvatarRemoved      = "admin.user_avatar_removed"
	AuditProviderAvatarImported      = "provider.avatar_imported"
	AuditProviderAvatarFailed        = "provider.avatar_import_failed"
	AuditMediaSettingsSaved          = "media.settings_saved"
	AuditMediaSettingsTested         = "media.settings_tested"
	AuditMediaMigrationStarted       = "media.migration_started"
	AuditMediaMigrationRetried       = "media.migration_retried"
	AuditMediaMigrationFinished      = "media.migration_finished"
	AuditMediaMigrationFailed        = "media.migration_failed"
	AuditTokenIssued                 = "token.issued"
	AuditTokenGrantFailed            = "token.grant_failed"
	AuditRefreshTokenReuse           = "token.refresh_reuse"
	AuditTokenRevoked                = "token.revoked"
	AuditServiceControlUpdated       = "service_control.updated"
	AuditServiceControlExpired       = "service_control.expired"
	AuditServiceControlCLIReset      = "service_control.cli_reset"
)

const (
	AuditHumanVerificationSaved       = "human_verification.settings_saved"
	AuditHumanVerificationTested      = "human_verification.settings_tested"
	AuditHumanVerificationActivated   = "human_verification.settings_activated"
	AuditHumanVerificationEnabled     = "human_verification.settings_enabled"
	AuditHumanVerificationUpdated     = "human_verification.policy_updated"
	AuditHumanVerificationDisabled    = "human_verification.settings_disabled"
	AuditHumanVerificationRolledBack  = "human_verification.settings_rolled_back"
	AuditHumanVerificationCLIDisabled = "human_verification.cli_disabled"
)
