package account

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/passwordpolicy"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	actionEnvelopePurpose = "account-action"
	emailEnvelopePurpose  = "email-outbox"
	maxUserAgentLength    = 512
)

type serviceStore interface {
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetUserByEmail(ctx context.Context, normalizedEmail string) (*models.User, error)
	GetPendingRegistrationByEmail(ctx context.Context, normalizedEmail string, now time.Time) (*models.User, time.Time, error)
	EmailInUse(ctx context.Context, normalizedEmail string, exceptUserID uuid.UUID) (bool, error)
	ReplaceActionAndQueueEmail(ctx context.Context, action *ActionToken, email *OutboxEmail) error
	ReplacePendingVerificationAndQueueEmail(ctx context.Context, expectedEmail string, action *ActionToken, email *OutboxEmail, now time.Time) error
	GetUsableAction(ctx context.Context, tokenHash []byte, action Action, now time.Time) (*ActionToken, error)
	ConsumePasswordReset(ctx context.Context, token *ActionToken, expectedEmail, passwordHash string, notices []*OutboxEmail, now time.Time) (*models.User, error)
	ConsumeEmailVerification(ctx context.Context, token *ActionToken, expectedEmail string, now time.Time) (*models.User, *time.Duration, error)
	ConsumeEmailChange(ctx context.Context, token *ActionToken, previousEmail, newEmail string, notices []*OutboxEmail, now time.Time) (*models.User, error)
}

type ServiceOptions struct {
	PublicBaseURL               string
	ActionOrigin                string
	ActiveKeyID                 string
	MasterKeys                  map[string][]byte
	PasswordResetTTL            time.Duration
	EmailActionTTL              time.Duration
	EmailOutboxTTL              time.Duration
	ReauthenticationTTL         time.Duration
	ReauthenticationTTLProvider func() time.Duration
	EmailPresentationProvider   func() EmailPresentation
	Clock                       func() time.Time
	GenerateToken               func() (string, error)
	OnEmailVerified             func(context.Context, time.Duration)
}

type Service struct {
	store                       serviceStore
	publicBaseURL               atomic.Pointer[url.URL]
	actionOrigin                string
	activeKeyID                 string
	masterKeys                  map[string][]byte
	passwordResetTTL            time.Duration
	emailActionTTL              time.Duration
	emailOutboxTTL              time.Duration
	reauthenticationTTL         time.Duration
	reauthenticationTTLProvider func() time.Duration
	emailPresentationProvider   func() EmailPresentation
	clock                       func() time.Time
	generateToken               func() (string, error)
	onEmailVerified             func(context.Context, time.Duration)
}

func NewService(store *Store, options ServiceOptions) (*Service, error) {
	return newService(store, options)
}

func newService(store serviceStore, options ServiceOptions) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("account store is required")
	}
	baseURL, err := url.Parse(strings.TrimSpace(options.PublicBaseURL))
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" || (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("public base URL must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	actionOrigin := (&url.URL{Scheme: baseURL.Scheme, Host: baseURL.Host}).String()
	if strings.TrimSpace(options.ActionOrigin) != "" {
		originURL, originErr := parsePublicBaseURL(options.ActionOrigin)
		if originErr != nil {
			return nil, fmt.Errorf("action origin is invalid: %w", originErr)
		}
		actionOrigin = (&url.URL{Scheme: originURL.Scheme, Host: originURL.Host}).String()
	}
	if !sameURLOrigin(baseURL, actionOrigin) {
		return nil, fmt.Errorf("public base URL must use the configured action origin")
	}
	if options.ActiveKeyID == "" {
		return nil, fmt.Errorf("active envelope key ID is required")
	}
	keys := make(map[string][]byte, len(options.MasterKeys))
	for keyID, key := range options.MasterKeys {
		if len(key) != 32 {
			return nil, fmt.Errorf("master key %q must contain exactly 32 bytes", keyID)
		}
		keys[keyID] = append([]byte(nil), key...)
	}
	if _, ok := keys[options.ActiveKeyID]; !ok {
		return nil, fmt.Errorf("active envelope key %q is unavailable", options.ActiveKeyID)
	}
	if options.PasswordResetTTL == 0 {
		options.PasswordResetTTL = 30 * time.Minute
	}
	if options.EmailActionTTL == 0 {
		options.EmailActionTTL = 24 * time.Hour
	}
	if options.EmailOutboxTTL == 0 {
		options.EmailOutboxTTL = 48 * time.Hour
	}
	if options.ReauthenticationTTL == 0 {
		options.ReauthenticationTTL = DefaultReauthenticationTTL
	}
	if options.PasswordResetTTL <= 0 || options.EmailActionTTL <= 0 || options.EmailOutboxTTL <= 0 || options.ReauthenticationTTL <= 0 {
		return nil, fmt.Errorf("account action TTLs must be positive")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.GenerateToken == nil {
		options.GenerateToken = func() (string, error) { return crypto.GenerateRandomString(32) }
	}
	service := &Service{
		store: store, activeKeyID: options.ActiveKeyID, masterKeys: keys, actionOrigin: actionOrigin,
		passwordResetTTL: options.PasswordResetTTL, emailActionTTL: options.EmailActionTTL,
		emailOutboxTTL: options.EmailOutboxTTL, reauthenticationTTL: options.ReauthenticationTTL,
		reauthenticationTTLProvider: options.ReauthenticationTTLProvider,
		emailPresentationProvider:   options.EmailPresentationProvider,
		clock:                       options.Clock, generateToken: options.GenerateToken, onEmailVerified: options.OnEmailVerified,
	}
	service.publicBaseURL.Store(baseURL)
	return service, nil
}

// SetPublicBaseURL atomically changes links rendered into subsequently queued
// account emails. Messages already in the outbox remain unchanged.
func (s *Service) SetPublicBaseURL(value string) error {
	baseURL, err := parsePublicBaseURL(value)
	if err != nil {
		return err
	}
	if !sameURLOrigin(baseURL, s.actionOrigin) {
		return fmt.Errorf("public base URL must use the configured action origin")
	}
	s.publicBaseURL.Store(baseURL)
	return nil
}

func sameURLOrigin(value *url.URL, expected string) bool {
	if value == nil {
		return false
	}
	return strings.EqualFold((&url.URL{Scheme: value.Scheme, Host: value.Host}).String(), expected)
}

func parsePublicBaseURL(value string) (*url.URL, error) {
	baseURL, err := url.Parse(strings.TrimSpace(value))
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" || (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("public base URL must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	return baseURL, nil
}

// RequestPasswordReset deliberately returns nil for unknown, unverified, or
// inactive accounts so callers can provide a constant account-enumeration-safe response.
func (s *Service) RequestPasswordReset(ctx context.Context, email string, metadata RequestMetadata) error {
	normalized, err := normalizeEmail(email)
	if err != nil {
		// Malformed addresses have the same externally observable result as an
		// address that does not belong to an account.
		return nil
	}
	accountUser, err := s.store.GetUserByEmail(ctx, normalized)
	if err != nil {
		if IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("looking up password recovery account: %w", err)
	}
	if accountUser.Status != models.UserStatusActive || accountUser.Email == nil || accountUser.EmailVerifiedAt == nil {
		return nil
	}
	return s.createActionEmail(ctx, accountUser, ActionPasswordReset, actionClaims{Email: normalized}, metadata, s.clock().UTC().Add(s.passwordResetTTL))
}

func (s *Service) ConfirmPasswordReset(ctx context.Context, rawToken, newPassword string) (*models.User, error) {
	if err := validatePassword(newPassword); err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	token, claims, err := s.loadAction(ctx, rawToken, ActionPasswordReset, now)
	if err != nil {
		return nil, err
	}
	passwordHash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return nil, fmt.Errorf("hashing replacement password: %w", err)
	}
	message, err := s.templateMessage(MessagePasswordChanged, claims.Email, EmailRenderData{})
	if err != nil {
		return nil, err
	}
	notice, err := s.newOutboxEmail(token.UserID, MessagePasswordChanged, message, now)
	if err != nil {
		return nil, err
	}
	updated, err := s.store.ConsumePasswordReset(ctx, token, claims.Email, passwordHash, []*OutboxEmail{notice}, now)
	if err != nil {
		return nil, normalizeConsumeError(err)
	}
	return updated, nil
}

func (s *Service) RequestEmailVerification(ctx context.Context, userID uuid.UUID, metadata RequestMetadata) error {
	accountUser, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("loading account for email verification: %w", err)
	}
	// Pending accounts are self-registrations waiting on exactly this email.
	if (accountUser.Status != models.UserStatusActive && accountUser.Status != models.UserStatusPending) || accountUser.Email == nil {
		return ErrAccountUnavailable
	}
	if accountUser.EmailVerifiedAt != nil {
		return nil
	}
	normalized, err := normalizeEmail(*accountUser.Email)
	if err != nil {
		return fmt.Errorf("%w: account email is invalid", ErrInvalidInput)
	}
	return s.createActionEmail(ctx, accountUser, ActionEmailVerification, actionClaims{Email: normalized}, metadata, s.clock().UTC().Add(s.emailActionTTL))
}

// PrepareEmailVerification completes token generation, envelope encryption,
// and email rendering without writing to the database. Public registration
// uses it before opening the transaction that creates the account.
func (s *Service) PrepareEmailVerification(accountUser *models.User, metadata RequestMetadata, expiresAt time.Time) (*PreparedActionEmail, error) {
	if accountUser == nil || accountUser.Email == nil || accountUser.Status != models.UserStatusPending {
		return nil, ErrAccountUnavailable
	}
	normalized, err := normalizeEmail(*accountUser.Email)
	if err != nil {
		return nil, fmt.Errorf("%w: account email is invalid", ErrInvalidInput)
	}
	return s.prepareActionEmail(
		accountUser,
		ActionEmailVerification,
		actionClaims{Email: normalized},
		metadata,
		expiresAt.UTC(),
	)
}

// RequestPendingEmailVerification is intentionally enumeration-safe. Unknown,
// active, and expired accounts all complete without a write or a distinct
// error. A matching pending registration receives a replacement token whose
// deadline remains the registration's persisted deadline.
func (s *Service) RequestPendingEmailVerification(ctx context.Context, email string, metadata RequestMetadata) error {
	normalized, err := normalizeEmail(email)
	if err != nil {
		return nil
	}
	now := s.clock().UTC()
	accountUser, expiresAt, err := s.store.GetPendingRegistrationByEmail(ctx, normalized, now)
	if err != nil {
		if IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("looking up pending email verification: %w", err)
	}
	prepared, err := s.prepareActionEmail(
		accountUser,
		ActionEmailVerification,
		actionClaims{Email: normalized},
		metadata,
		expiresAt,
	)
	if err != nil {
		return err
	}
	if err := s.store.ReplacePendingVerificationAndQueueEmail(
		ctx, normalized, prepared.Action, prepared.Email, now,
	); err != nil {
		return fmt.Errorf("persisting pending email verification: %w", err)
	}
	return nil
}

func (s *Service) ConfirmEmailVerification(ctx context.Context, rawToken string) (*models.User, error) {
	now := s.clock().UTC()
	token, claims, err := s.loadAction(ctx, rawToken, ActionEmailVerification, now)
	if err != nil {
		return nil, err
	}
	updated, verificationDuration, err := s.store.ConsumeEmailVerification(ctx, token, claims.Email, now)
	if err != nil {
		return nil, normalizeConsumeError(err)
	}
	if verificationDuration != nil && s.onEmailVerified != nil {
		s.onEmailVerified(ctx, *verificationDuration)
	}
	return updated, nil
}

func (s *Service) RequestEmailChange(ctx context.Context, userID uuid.UUID, newEmail string, authenticatedAt time.Time, metadata RequestMetadata) error {
	now := s.clock().UTC()
	if authenticatedAt.IsZero() || authenticatedAt.After(now.Add(time.Minute)) || now.Sub(authenticatedAt) > s.currentReauthenticationTTL() {
		return ErrRecentAuthenticationRequired
	}
	normalized, err := normalizeEmail(newEmail)
	if err != nil {
		return err
	}
	accountUser, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("loading account for email change: %w", err)
	}
	if accountUser.Status != models.UserStatusActive {
		return ErrAccountUnavailable
	}
	previousEmail := ""
	if accountUser.Email != nil {
		previousEmail, err = normalizeEmail(*accountUser.Email)
		if err != nil {
			return fmt.Errorf("%w: current account email is invalid", ErrInvalidInput)
		}
	}
	if strings.EqualFold(previousEmail, normalized) {
		return fmt.Errorf("%w: new email must differ from the current email", ErrInvalidInput)
	}
	inUse, err := s.store.EmailInUse(ctx, normalized, userID)
	if err != nil {
		return fmt.Errorf("checking email availability: %w", err)
	}
	if inUse {
		return ErrEmailInUse
	}
	return s.createActionEmail(ctx, accountUser, ActionEmailChange, actionClaims{Email: normalized, PreviousEmail: previousEmail}, metadata, s.clock().UTC().Add(s.emailActionTTL))
}

func (s *Service) currentReauthenticationTTL() time.Duration {
	if s.reauthenticationTTLProvider != nil {
		if value := s.reauthenticationTTLProvider(); value > 0 {
			return value
		}
	}
	return s.reauthenticationTTL
}

func (s *Service) ConfirmEmailChange(ctx context.Context, rawToken string) (*models.User, error) {
	now := s.clock().UTC()
	token, claims, err := s.loadAction(ctx, rawToken, ActionEmailChange, now)
	if err != nil {
		return nil, err
	}
	notices := make([]*OutboxEmail, 0, 2)
	if claims.PreviousEmail != "" {
		message, err := s.templateMessage(MessageEmailChangedOld, claims.PreviousEmail, EmailRenderData{})
		if err != nil {
			return nil, err
		}
		oldNotice, err := s.newOutboxEmail(token.UserID, MessageEmailChangedOld, message, now)
		if err != nil {
			return nil, err
		}
		notices = append(notices, oldNotice)
	}
	message, err := s.templateMessage(MessageEmailChangedNew, claims.Email, EmailRenderData{})
	if err != nil {
		return nil, err
	}
	newNotice, err := s.newOutboxEmail(token.UserID, MessageEmailChangedNew, message, now)
	if err != nil {
		return nil, err
	}
	notices = append(notices, newNotice)
	updated, err := s.store.ConsumeEmailChange(ctx, token, claims.PreviousEmail, claims.Email, notices, now)
	if err != nil {
		return nil, normalizeConsumeError(err)
	}
	return updated, nil
}

// BuildSecurityNotification creates an encrypted email-outbox item from a
// fixed template. Missing or unverified email capability deliberately returns
// nil so security-sensitive mutations are not blocked for accounts that cannot
// receive mail.
func (s *Service) BuildSecurityNotification(accountUser *models.User, notice SecurityNotice) (*OutboxEmail, error) {
	if accountUser == nil {
		return nil, fmt.Errorf("security notification user is required")
	}
	if accountUser.Email == nil || accountUser.EmailVerifiedAt == nil || strings.TrimSpace(*accountUser.Email) == "" {
		return nil, nil
	}
	recipient, err := normalizeEmail(*accountUser.Email)
	if err != nil {
		return nil, fmt.Errorf("security notification recipient is invalid: %w", err)
	}
	data, err := securityNotificationRenderData(notice)
	if err != nil {
		return nil, err
	}
	message, err := s.templateMessage(notice.MessageType, recipient, data)
	if err != nil {
		return nil, err
	}
	return s.newOutboxEmail(accountUser.ID, notice.MessageType, message, s.clock().UTC())
}

func securityNotificationRenderData(notice SecurityNotice) (EmailRenderData, error) {
	data := EmailRenderData{}
	switch notice.MessageType {
	case MessageRoleChanged:
		if notice.Role != "admin" && notice.Role != "user" {
			return EmailRenderData{}, fmt.Errorf("invalid security notification role")
		}
		data.Role = notice.Role
	case MessageStatusChanged:
		switch notice.Status {
		case string(models.UserStatusActive), string(models.UserStatusSuspended), string(models.UserStatusPending):
		default:
			return EmailRenderData{}, fmt.Errorf("invalid security notification status")
		}
		data.Status = notice.Status
	case MessagePasswordChanged, MessagePasswordConfigured, MessagePasswordResetAdmin:
	case MessageIdentityBound, MessageIdentityUnbound:
		providerName := strings.TrimSpace(notice.Provider)
		if !validSecurityNoticeProvider(providerName) {
			return EmailRenderData{}, fmt.Errorf("invalid security notification provider")
		}
		data.Provider = providerName
	default:
		return EmailRenderData{}, fmt.Errorf("unsupported security notification type")
	}
	return data, nil
}

func validSecurityNoticeProvider(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func (s *Service) createActionEmail(ctx context.Context, accountUser *models.User, action Action, claims actionClaims, metadata RequestMetadata, expiresAt time.Time) error {
	prepared, err := s.prepareActionEmail(accountUser, action, claims, metadata, expiresAt)
	if err != nil {
		return err
	}
	if err := s.store.ReplaceActionAndQueueEmail(ctx, prepared.Action, prepared.Email); err != nil {
		return fmt.Errorf("persisting account action: %w", err)
	}
	return nil
}

func (s *Service) prepareActionEmail(accountUser *models.User, action Action, claims actionClaims, metadata RequestMetadata, expiresAt time.Time) (*PreparedActionEmail, error) {
	rawToken, err := s.generateToken()
	if err != nil {
		return nil, fmt.Errorf("generating account action token: %w", err)
	}
	if len(rawToken) < 32 {
		return nil, fmt.Errorf("generated account action token is too short")
	}
	now := s.clock().UTC()
	expiresAt = expiresAt.UTC()
	if !expiresAt.After(now) {
		return nil, fmt.Errorf("account action expiry must be in the future")
	}
	ttl := expiresAt.Sub(now)
	requestIP, userAgent := sanitizeMetadata(metadata)
	token := &ActionToken{
		ID: uuid.New(), UserID: accountUser.ID, Action: action, TokenHash: HashActionToken(rawToken),
		RequestedIP: requestIP, UserAgent: userAgent, ExpiresAt: expiresAt, CreatedAt: now,
	}
	encodedClaims, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("encoding account action claims: %w", err)
	}
	token.PayloadCiphertext, err = crypto.EncryptEnvelope(
		s.masterKeys[s.activeKeyID], s.activeKeyID, actionEnvelopePurpose, encodedClaims, actionAAD(token),
	)
	if err != nil {
		return nil, fmt.Errorf("encrypting account action claims: %w", err)
	}
	message, err := s.actionMessage(action, claims.Email, accountUser.Username, rawToken, ttl)
	if err != nil {
		return nil, err
	}
	outbox, err := s.newOutboxEmail(accountUser.ID, messageTypeForAction(action), message, now)
	if err != nil {
		return nil, err
	}
	if outbox.ExpiresAt.After(expiresAt) {
		outbox.ExpiresAt = expiresAt
	}
	return &PreparedActionEmail{Action: token, Email: outbox}, nil
}

func (s *Service) loadAction(ctx context.Context, rawToken string, action Action, now time.Time) (*ActionToken, actionClaims, error) {
	if len(rawToken) < 32 || len(rawToken) > 1024 {
		return nil, actionClaims{}, ErrInvalidActionToken
	}
	token, err := s.store.GetUsableAction(ctx, HashActionToken(rawToken), action, now)
	if err != nil {
		return nil, actionClaims{}, normalizeConsumeError(err)
	}
	plaintext, err := crypto.DecryptEnvelope(s.masterKeys, actionEnvelopePurpose, token.PayloadCiphertext, actionAAD(token))
	if err != nil {
		return nil, actionClaims{}, fmt.Errorf("%w: account action claims failed authentication", ErrInvalidActionToken)
	}
	var claims actionClaims
	if err := json.Unmarshal(plaintext, &claims); err != nil {
		return nil, actionClaims{}, fmt.Errorf("%w: account action claims are malformed", ErrInvalidActionToken)
	}
	claims.Email, err = normalizeEmail(claims.Email)
	if err != nil {
		return nil, actionClaims{}, fmt.Errorf("invalid encrypted account action claims: %w", err)
	}
	if claims.PreviousEmail != "" {
		claims.PreviousEmail, err = normalizeEmail(claims.PreviousEmail)
		if err != nil {
			return nil, actionClaims{}, fmt.Errorf("invalid encrypted account action claims: %w", err)
		}
	}
	return token, claims, nil
}

func (s *Service) newOutboxEmail(userID uuid.UUID, messageType string, message EmailMessage, now time.Time) (*OutboxEmail, error) {
	if err := validateEmailMessage(message); err != nil {
		return nil, fmt.Errorf("validating email before outbox encryption: %w", err)
	}
	id := uuid.New()
	encoded, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("encoding email outbox message: %w", err)
	}
	encrypted, err := crypto.EncryptEnvelope(
		s.masterKeys[s.activeKeyID], s.activeKeyID, emailEnvelopePurpose, encoded, emailAAD(id, messageType, userID),
	)
	if err != nil {
		return nil, fmt.Errorf("encrypting email outbox message: %w", err)
	}
	recipientDigest := sha256.Sum256([]byte(strings.ToLower(message.To)))
	return &OutboxEmail{
		ID: id, UserID: &userID, MessageType: messageType, RecipientHash: recipientDigest[:],
		EncryptedMessage: encrypted, Status: "pending", AvailableAt: now,
		ExpiresAt: now.Add(s.emailOutboxTTL), CreatedAt: now,
	}, nil
}

func (s *Service) actionMessage(action Action, recipient, username, rawToken string, ttl time.Duration) (EmailMessage, error) {
	ttlText := formatActionTTL(ttl)
	var path, messageType string
	switch action {
	case ActionPasswordReset:
		path, messageType = "/reset-password", MessagePasswordReset
	case ActionEmailVerification:
		path, messageType = "/verify-email", MessageEmailVerification
	case ActionEmailChange:
		path, messageType = "/change-email", MessageEmailChangeConfirm
	default:
		return EmailMessage{}, fmt.Errorf("unsupported account action %q", action)
	}
	baseURL := s.publicBaseURL.Load()
	if baseURL == nil {
		return EmailMessage{}, fmt.Errorf("public base URL is unavailable")
	}
	actionURL := *baseURL
	actionURL.Path = strings.TrimSuffix(actionURL.Path, "/") + path
	query := actionURL.Query()
	query.Set("token", rawToken)
	actionURL.RawQuery = query.Encode()
	return s.templateMessage(messageType, recipient, EmailRenderData{
		Username: username, TTL: ttlText, ActionURL: actionURL.String(),
	})
}

func (s *Service) templateMessage(messageType, recipient string, data EmailRenderData) (EmailMessage, error) {
	presentation := EmailPresentation{SiteName: "Nyauth", Settings: DefaultEmailTemplateSettings()}
	if s.emailPresentationProvider != nil {
		presentation = s.emailPresentationProvider()
	}
	return RenderEmailTemplate(messageType, recipient, presentation, data)
}

func formatActionTTL(ttl time.Duration) string {
	if ttl%time.Hour == 0 {
		return fmt.Sprintf("%d 小时", int(ttl/time.Hour))
	}
	if ttl%time.Minute == 0 {
		return fmt.Sprintf("%d 分钟", int(ttl/time.Minute))
	}
	return ttl.Round(time.Second).String()
}

func HashActionToken(rawToken string) []byte {
	digest := sha256.Sum256([]byte(rawToken))
	return append([]byte(nil), digest[:]...)
}

func actionAAD(token *ActionToken) []byte {
	return []byte(token.ID.String() + "\x00" + token.UserID.String() + "\x00" + string(token.Action))
}

func emailAAD(id uuid.UUID, messageType string, userID uuid.UUID) []byte {
	return []byte(id.String() + "\x00" + userID.String() + "\x00" + messageType)
}

func messageTypeForAction(action Action) string {
	switch action {
	case ActionPasswordReset:
		return MessagePasswordReset
	case ActionEmailVerification:
		return MessageEmailVerification
	case ActionEmailChange:
		return MessageEmailChangeConfirm
	default:
		return "account.unknown"
	}
}

func normalizeEmail(value string) (string, error) {
	value = strings.TrimSpace(value)
	parsed, err := mail.ParseAddress(value)
	if err != nil || !strings.EqualFold(parsed.Address, value) || len(value) > 255 {
		return "", fmt.Errorf("%w: invalid email address", ErrInvalidInput)
	}
	return strings.ToLower(parsed.Address), nil
}

func validatePassword(password string) error {
	if err := passwordpolicy.Validate(password); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidInput, err)
	}
	return nil
}

func sanitizeMetadata(metadata RequestMetadata) (*string, *string) {
	var ipAddress *string
	if parsed := net.ParseIP(strings.TrimSpace(metadata.IPAddress)); parsed != nil {
		value := parsed.String()
		ipAddress = &value
	}
	userAgentValue := strings.TrimSpace(metadata.UserAgent)
	if len(userAgentValue) > maxUserAgentLength {
		userAgentValue = userAgentValue[:maxUserAgentLength]
		for !utf8.ValidString(userAgentValue) {
			userAgentValue = userAgentValue[:len(userAgentValue)-1]
		}
	}
	var userAgent *string
	if userAgentValue != "" {
		userAgent = &userAgentValue
	}
	return ipAddress, userAgent
}

func normalizeConsumeError(err error) error {
	if err == nil {
		return nil
	}
	if IsNotFound(err) || errors.Is(err, ErrInvalidActionToken) {
		return ErrInvalidActionToken
	}
	return err
}
