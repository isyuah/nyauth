package audit

import (
	"sort"

	"github.com/nyasharp/nyauth/pkg/models"
)

type FilterOptions struct {
	Events      []string `json:"events"`
	Results     []string `json:"results"`
	Risks       []string `json:"risks"`
	TargetTypes []string `json:"target_types"`
}

// KnownFilterOptions returns the bounded audit vocabulary emitted by Nyauth.
// It is static by design so loading the filter UI never scans retained audit
// partitions or reflects arbitrary database values back into the control plane.
func KnownFilterOptions() FilterOptions {
	events := []string{
		"account.action_requested",
		models.AuditAuthorizationRevoked,
		models.AuditAuthorizeDenied,
		models.AuditClientAccessChanged,
		models.AuditClientCreated,
		models.AuditClientDeleted,
		models.AuditClientOwnerChanged,
		models.AuditClientSecretRotated,
		models.AuditClientUpdated,
		models.AuditConsentAccepted,
		models.AuditConsentDenied,
		models.AuditIdentityBindStarted,
		models.AuditIdentityBound,
		models.AuditIdentityUnbound,
		models.AuditInviteConsumed,
		models.AuditInviteCreated,
		models.AuditInviteReleased,
		models.AuditInviteReserved,
		models.AuditInviteRevoked,
		models.AuditMFAChallengeFailed,
		models.AuditMFADisabled,
		models.AuditMFAEnrolled,
		models.AuditMailCircuitOpened,
		models.AuditMailCircuitRecovered,
		models.AuditMailSettingsActivated,
		models.AuditMailSettingsDisabled,
		models.AuditMailSettingsRolledBack,
		models.AuditMailSettingsSaved,
		models.AuditMailSettingsTested,
		models.AuditMediaSettingsSaved,
		models.AuditMediaSettingsTested,
		models.AuditMediaMigrationStarted,
		models.AuditMediaMigrationRetried,
		models.AuditMediaMigrationFinished,
		models.AuditMediaMigrationFailed,
		models.AuditPasskeyLogin,
		models.AuditPasskeyRegistered,
		models.AuditPasskeyRemoved,
		models.AuditPasskeyRenamed,
		models.AuditProviderAvatarFailed,
		models.AuditProviderAvatarImported,
		models.AuditProviderCreated,
		models.AuditProviderDeleted,
		models.AuditProviderTested,
		models.AuditProviderUpdated,
		models.AuditRecoveryCodesGenerated,
		models.AuditRecoveryCodeUsed,
		models.AuditRefreshTokenReuse,
		models.AuditRegistrationExpired,
		models.AuditSettingsUpdated,
		models.AuditTokenGrantFailed,
		models.AuditTokenIssued,
		models.AuditTokenRevoked,
		models.AuditAdminUserAvatarRemoved,
		models.AuditAdminUserAvatarUpdated,
		models.AuditUserActivated,
		models.AuditUserAvatarRemoved,
		models.AuditUserAvatarUpdated,
		models.AuditUserCreated,
		models.AuditUserDeleted,
		models.AuditUserEmailChanged,
		models.AuditUserEmailVerified,
		models.AuditEmailChangeRequested,
		models.AuditEmailVerifyRequested,
		models.AuditUserLogin,
		models.AuditUserLoginFailed,
		models.AuditUserLogout,
		models.AuditUserPasswordChanged,
		models.AuditUserPasswordReset,
		models.AuditUserPasswordSet,
		models.AuditUserProfileUpdated,
		"user.reauthenticated",
		models.AuditUserRegistered,
		models.AuditUserRoleChanged,
		models.AuditUserSessionsRevoked,
		models.AuditUserSuspended,
		models.AuditUserUpdated,
		models.AuditSessionOthersRevoked,
		models.AuditSessionRevoked,
	}
	sort.Strings(events)
	return FilterOptions{
		Events:  events,
		Results: []string{"failure", "success"},
		Risks:   []string{"critical", "high", "low", "medium"},
		TargetTypes: []string{
			"client", "identity", "invite", "mail_config", "mail_runtime", "media_config", "media_migration", "oauth_consent",
			"oauth_endpoint", "oauth_grant", "passkey", "provider", "registration",
			"session", "settings", "user",
		},
	}
}
