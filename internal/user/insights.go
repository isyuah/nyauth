package user

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

type AdminUserReference struct {
	ID          uuid.UUID `json:"id"`
	Username    string    `json:"username"`
	DisplayName *string   `json:"display_name,omitempty"`
}

type SelfRegistrationSummary struct {
	Status        string     `json:"status"`
	InviteID      *uuid.UUID `json:"invite_id,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	ReleasedAt    *time.Time `json:"released_at,omitempty"`
	ReleaseReason *string    `json:"release_reason,omitempty"`
}

type AdminUserOverview struct {
	User             models.User              `json:"user"`
	CreationSource   string                   `json:"creation_source"`
	CreatedBy        *AdminUserReference      `json:"created_by"`
	SelfRegistration *SelfRegistrationSummary `json:"self_registration"`
}

type AdminUserSecurity struct {
	HasPassword             bool              `json:"has_password"`
	PasswordChangedAt       *time.Time        `json:"password_changed_at,omitempty"`
	MustChangePassword      bool              `json:"must_change_password"`
	TOTPAvailable           bool              `json:"totp_available"`
	TOTPEnrolled            bool              `json:"totp_enrolled"`
	RecoveryCodesRemaining  int               `json:"recovery_codes_remaining"`
	PasskeysAvailable       bool              `json:"passkeys_available"`
	PasskeysEnrolled        int               `json:"passkeys_enrolled"`
	PasskeyCloneWarnings    int               `json:"passkey_clone_warnings"`
	LastPasskeyUsedAt       *time.Time        `json:"last_passkey_used_at,omitempty"`
	MFARequiredForAdmin     bool              `json:"mfa_required_for_admin"`
	MFARequirementSatisfied bool              `json:"mfa_requirement_satisfied"`
	UserStatus              models.UserStatus `json:"-"`
	UserRole                string            `json:"-"`
}

const adminOverviewUserSelectCols = `
	subject.id,subject.username,subject.email,subject.email_verified_at,
	subject.password_hash,subject.password_changed_at,subject.display_name,
	CASE WHEN subject.current_avatar_id IS NULL THEN NULL ELSE '/media/avatars/' || subject.current_avatar_id::text || '/256.webp' END AS avatar_url,
	subject.status,subject.role,subject.auth_version,subject.session_version,
	subject.must_change_password,subject.login_mfa_enabled,subject.last_authenticated_at,subject.last_login_at,
	subject.last_login_ip,subject.metadata,subject.created_at,subject.updated_at`

func (s *Store) GetAdminOverview(ctx context.Context, id uuid.UUID) (*AdminUserOverview, error) {
	overview := &AdminUserOverview{}
	var createdByID *uuid.UUID
	var createdByUsername, createdByDisplayName *string
	var registrationStatus, releaseReason *string
	var inviteID *uuid.UUID
	var expiresAt, completedAt, releasedAt *time.Time
	destinations := userScanDestinations(&overview.User)
	destinations = append(
		destinations,
		&overview.CreationSource,
		&createdByID,
		&createdByUsername,
		&createdByDisplayName,
		&registrationStatus,
		&inviteID,
		&expiresAt,
		&completedAt,
		&releasedAt,
		&releaseReason,
	)
	err := s.db.QueryRow(ctx, `
		SELECT `+adminOverviewUserSelectCols+`,
			subject.creation_source,
			creator.id,creator.username,creator.display_name,
			registration.status,registration.invite_id,registration.expires_at,
			registration.completed_at,registration.released_at,registration.release_reason
		FROM users AS subject
		LEFT JOIN users AS creator ON creator.id=subject.created_by
		LEFT JOIN self_registrations AS registration ON registration.user_id=subject.id
		WHERE subject.id=$1
	`, id).Scan(destinations...)
	if err != nil {
		return nil, fmt.Errorf("loading administrator user overview: %w", err)
	}
	if createdByID != nil {
		username := ""
		if createdByUsername != nil {
			username = *createdByUsername
		}
		overview.CreatedBy = &AdminUserReference{
			ID: *createdByID, Username: username, DisplayName: createdByDisplayName,
		}
	}
	if registrationStatus != nil && expiresAt != nil {
		overview.SelfRegistration = &SelfRegistrationSummary{
			Status: *registrationStatus, InviteID: inviteID, ExpiresAt: expiresAt.UTC(),
			CompletedAt: completedAt, ReleasedAt: releasedAt, ReleaseReason: releaseReason,
		}
	}
	return overview, nil
}

func (s *Store) GetAdminSecurity(ctx context.Context, id uuid.UUID) (*AdminUserSecurity, error) {
	result := &AdminUserSecurity{}
	err := s.db.QueryRow(ctx, `
		SELECT
			subject.password_hash IS NOT NULL,
			subject.password_changed_at,
			subject.must_change_password,
			subject.status,
			subject.role,
			EXISTS (
				SELECT 1 FROM user_totp_credentials
				WHERE user_id=subject.id AND confirmed_at IS NOT NULL
			),
			(
				SELECT COUNT(*) FROM user_recovery_codes
				WHERE user_id=subject.id AND used_at IS NULL
			),
			(
				SELECT COUNT(*) FROM user_passkey_credentials
				WHERE user_id=subject.id AND ($2='' OR rp_id=$2)
			),
			(
				SELECT COUNT(*) FROM user_passkey_credentials
				WHERE user_id=subject.id AND ($2='' OR rp_id=$2) AND clone_warning
			),
			(
				SELECT MAX(last_used_at) FROM user_passkey_credentials
				WHERE user_id=subject.id AND ($2='' OR rp_id=$2)
			)
		FROM users AS subject
		WHERE subject.id=$1
	`, id, s.passkeyRPID).Scan(
		&result.HasPassword,
		&result.PasswordChangedAt,
		&result.MustChangePassword,
		&result.UserStatus,
		&result.UserRole,
		&result.TOTPEnrolled,
		&result.RecoveryCodesRemaining,
		&result.PasskeysEnrolled,
		&result.PasskeyCloneWarnings,
		&result.LastPasskeyUsedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("loading administrator user security: %w", err)
	}
	return result, nil
}

type adminInsightsStore interface {
	GetAdminOverview(ctx context.Context, id uuid.UUID) (*AdminUserOverview, error)
	GetAdminSecurity(ctx context.Context, id uuid.UUID) (*AdminUserSecurity, error)
}

func (s *Service) GetAdminOverview(ctx context.Context, id uuid.UUID) (*AdminUserOverview, error) {
	store, ok := s.store.(adminInsightsStore)
	if !ok {
		return nil, fmt.Errorf("administrator user overview is unavailable")
	}
	return store.GetAdminOverview(ctx, id)
}

func (s *Service) GetAdminSecurity(ctx context.Context, id uuid.UUID) (*AdminUserSecurity, error) {
	store, ok := s.store.(adminInsightsStore)
	if !ok {
		return nil, fmt.Errorf("administrator user security is unavailable")
	}
	return store.GetAdminSecurity(ctx, id)
}
