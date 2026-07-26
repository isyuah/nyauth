package account

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net"
	"net/mail"
	"net/url"
	"strings"
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
	EmailInUse(ctx context.Context, normalizedEmail string, exceptUserID uuid.UUID) (bool, error)
	ReplaceActionAndQueueEmail(ctx context.Context, action *ActionToken, email *OutboxEmail) error
	GetUsableAction(ctx context.Context, tokenHash []byte, action Action, now time.Time) (*ActionToken, error)
	ConsumePasswordReset(ctx context.Context, token *ActionToken, expectedEmail, passwordHash string, notices []*OutboxEmail, now time.Time) (*models.User, error)
	ConsumeEmailVerification(ctx context.Context, token *ActionToken, expectedEmail string, now time.Time) (*models.User, error)
	ConsumeEmailChange(ctx context.Context, token *ActionToken, previousEmail, newEmail string, notices []*OutboxEmail, now time.Time) (*models.User, error)
}

type ServiceOptions struct {
	PublicBaseURL       string
	ActiveKeyID         string
	MasterKeys          map[string][]byte
	PasswordResetTTL    time.Duration
	EmailActionTTL      time.Duration
	EmailOutboxTTL      time.Duration
	ReauthenticationTTL time.Duration
	Clock               func() time.Time
	GenerateToken       func() (string, error)
}

type Service struct {
	store               serviceStore
	publicBaseURL       *url.URL
	activeKeyID         string
	masterKeys          map[string][]byte
	passwordResetTTL    time.Duration
	emailActionTTL      time.Duration
	emailOutboxTTL      time.Duration
	reauthenticationTTL time.Duration
	clock               func() time.Time
	generateToken       func() (string, error)
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
	return &Service{
		store: store, publicBaseURL: baseURL, activeKeyID: options.ActiveKeyID, masterKeys: keys,
		passwordResetTTL: options.PasswordResetTTL, emailActionTTL: options.EmailActionTTL,
		emailOutboxTTL: options.EmailOutboxTTL, reauthenticationTTL: options.ReauthenticationTTL,
		clock: options.Clock, generateToken: options.GenerateToken,
	}, nil
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
	return s.createActionEmail(ctx, accountUser, ActionPasswordReset, actionClaims{Email: normalized}, metadata, s.passwordResetTTL)
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
	notice, err := s.newOutboxEmail(token.UserID, MessagePasswordChanged, EmailMessage{
		To: claims.Email, Subject: "Nyauth 密码已重置",
		TextBody: "您的 Nyauth 密码刚刚被重置。如果这不是您本人操作，请立即联系管理员。",
		HTMLBody: "<p>您的 Nyauth 密码刚刚被重置。</p><p>如果这不是您本人操作，请立即联系管理员。</p>",
	}, now)
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
	if accountUser.Status != models.UserStatusActive || accountUser.Email == nil {
		return ErrAccountUnavailable
	}
	if accountUser.EmailVerifiedAt != nil {
		return nil
	}
	normalized, err := normalizeEmail(*accountUser.Email)
	if err != nil {
		return fmt.Errorf("%w: account email is invalid", ErrInvalidInput)
	}
	return s.createActionEmail(ctx, accountUser, ActionEmailVerification, actionClaims{Email: normalized}, metadata, s.emailActionTTL)
}

func (s *Service) ConfirmEmailVerification(ctx context.Context, rawToken string) (*models.User, error) {
	now := s.clock().UTC()
	token, claims, err := s.loadAction(ctx, rawToken, ActionEmailVerification, now)
	if err != nil {
		return nil, err
	}
	updated, err := s.store.ConsumeEmailVerification(ctx, token, claims.Email, now)
	if err != nil {
		return nil, normalizeConsumeError(err)
	}
	return updated, nil
}

func (s *Service) RequestEmailChange(ctx context.Context, userID uuid.UUID, newEmail string, authenticatedAt time.Time, metadata RequestMetadata) error {
	now := s.clock().UTC()
	if authenticatedAt.IsZero() || authenticatedAt.After(now.Add(time.Minute)) || now.Sub(authenticatedAt) > s.reauthenticationTTL {
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
	return s.createActionEmail(ctx, accountUser, ActionEmailChange, actionClaims{Email: normalized, PreviousEmail: previousEmail}, metadata, s.emailActionTTL)
}

func (s *Service) ConfirmEmailChange(ctx context.Context, rawToken string) (*models.User, error) {
	now := s.clock().UTC()
	token, claims, err := s.loadAction(ctx, rawToken, ActionEmailChange, now)
	if err != nil {
		return nil, err
	}
	notices := make([]*OutboxEmail, 0, 2)
	if claims.PreviousEmail != "" {
		oldNotice, err := s.newOutboxEmail(token.UserID, MessageEmailChangedOld, EmailMessage{
			To: claims.PreviousEmail, Subject: "Nyauth 邮箱地址已变更",
			TextBody: "您的 Nyauth 账户邮箱地址刚刚被变更。如果这不是您本人操作，请立即联系管理员。",
			HTMLBody: "<p>您的 Nyauth 账户邮箱地址刚刚被变更。</p><p>如果这不是您本人操作，请立即联系管理员。</p>",
		}, now)
		if err != nil {
			return nil, err
		}
		notices = append(notices, oldNotice)
	}
	newNotice, err := s.newOutboxEmail(token.UserID, MessageEmailChangedNew, EmailMessage{
		To: claims.Email, Subject: "Nyauth 新邮箱已确认",
		TextBody: "此邮箱现已绑定到您的 Nyauth 账户。",
		HTMLBody: "<p>此邮箱现已绑定到您的 Nyauth 账户。</p>",
	}, now)
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
	message, err := securityNotificationMessage(recipient, notice)
	if err != nil {
		return nil, err
	}
	return s.newOutboxEmail(accountUser.ID, notice.MessageType, message, s.clock().UTC())
}

func securityNotificationMessage(recipient string, notice SecurityNotice) (EmailMessage, error) {
	var subject, body string
	switch notice.MessageType {
	case MessageRoleChanged:
		if notice.Role != "admin" && notice.Role != "user" {
			return EmailMessage{}, fmt.Errorf("invalid security notification role")
		}
		subject = "Nyauth 账户角色已变更"
		body = "您的 Nyauth 账户角色已变更为“" + notice.Role + "”。"
	case MessageStatusChanged:
		switch notice.Status {
		case string(models.UserStatusActive), string(models.UserStatusSuspended), string(models.UserStatusPending):
		default:
			return EmailMessage{}, fmt.Errorf("invalid security notification status")
		}
		subject = "Nyauth 账户状态已变更"
		body = "您的 Nyauth 账户状态已变更为“" + notice.Status + "”。"
	case MessagePasswordChanged:
		subject = "Nyauth 密码已修改"
		body = "您的 Nyauth 本地密码刚刚被修改。"
	case MessagePasswordConfigured:
		subject = "Nyauth 本地密码已设置"
		body = "您的 Nyauth 账户刚刚设置了本地密码。"
	case MessagePasswordResetAdmin:
		subject = "Nyauth 密码已由管理员重置"
		body = "您的 Nyauth 本地密码刚刚由管理员重置，下一次登录时必须修改密码。"
	case MessageIdentityBound, MessageIdentityUnbound:
		providerName := strings.TrimSpace(notice.Provider)
		if !validSecurityNoticeProvider(providerName) {
			return EmailMessage{}, fmt.Errorf("invalid security notification provider")
		}
		if notice.MessageType == MessageIdentityBound {
			subject = "Nyauth 外部身份已绑定"
			body = "您的 Nyauth 账户刚刚绑定了外部身份“" + providerName + "”。"
		} else {
			subject = "Nyauth 外部身份已解绑"
			body = "您的 Nyauth 账户刚刚解绑了外部身份“" + providerName + "”。"
		}
	default:
		return EmailMessage{}, fmt.Errorf("unsupported security notification type")
	}
	body += " 如果这不是您本人或您信任的管理员操作，请立即联系管理员。"
	return EmailMessage{
		To: recipient, Subject: subject, TextBody: body,
		HTMLBody: "<p>" + html.EscapeString(body) + "</p>",
	}, nil
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

func (s *Service) createActionEmail(ctx context.Context, accountUser *models.User, action Action, claims actionClaims, metadata RequestMetadata, ttl time.Duration) error {
	rawToken, err := s.generateToken()
	if err != nil {
		return fmt.Errorf("generating account action token: %w", err)
	}
	if len(rawToken) < 32 {
		return fmt.Errorf("generated account action token is too short")
	}
	now := s.clock().UTC()
	requestIP, userAgent := sanitizeMetadata(metadata)
	token := &ActionToken{
		ID: uuid.New(), UserID: accountUser.ID, Action: action, TokenHash: HashActionToken(rawToken),
		RequestedIP: requestIP, UserAgent: userAgent, ExpiresAt: now.Add(ttl), CreatedAt: now,
	}
	encodedClaims, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("encoding account action claims: %w", err)
	}
	token.PayloadCiphertext, err = crypto.EncryptEnvelope(
		s.masterKeys[s.activeKeyID], s.activeKeyID, actionEnvelopePurpose, encodedClaims, actionAAD(token),
	)
	if err != nil {
		return fmt.Errorf("encrypting account action claims: %w", err)
	}
	message, err := s.actionMessage(action, claims.Email, rawToken, ttl)
	if err != nil {
		return err
	}
	outbox, err := s.newOutboxEmail(accountUser.ID, messageTypeForAction(action), message, now)
	if err != nil {
		return err
	}
	if err := s.store.ReplaceActionAndQueueEmail(ctx, token, outbox); err != nil {
		return fmt.Errorf("persisting account action: %w", err)
	}
	return nil
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

func (s *Service) actionMessage(action Action, recipient, rawToken string, ttl time.Duration) (EmailMessage, error) {
	var path, subject, lead string
	switch action {
	case ActionPasswordReset:
		path, subject, lead = "/reset-password", "重置 Nyauth 密码", "请在 "+formatActionTTL(ttl)+"内确认重置您的 Nyauth 密码。"
	case ActionEmailVerification:
		path, subject, lead = "/verify-email", "验证 Nyauth 邮箱", "请在 "+formatActionTTL(ttl)+"内确认此邮箱属于您的 Nyauth 账户。"
	case ActionEmailChange:
		path, subject, lead = "/change-email", "确认 Nyauth 邮箱变更", "请在 "+formatActionTTL(ttl)+"内确认将此邮箱绑定到您的 Nyauth 账户。"
	default:
		return EmailMessage{}, fmt.Errorf("unsupported account action %q", action)
	}
	actionURL := *s.publicBaseURL
	actionURL.Path = strings.TrimSuffix(actionURL.Path, "/") + path
	query := actionURL.Query()
	query.Set("token", rawToken)
	actionURL.RawQuery = query.Encode()
	link := actionURL.String()
	return EmailMessage{
		To: recipient, Subject: subject,
		TextBody: lead + "\n\n" + link + "\n\n如果这不是您本人操作，可以忽略此邮件。",
		HTMLBody: "<p>" + html.EscapeString(lead) + "</p><p><a href=\"" + html.EscapeString(link) + "\">继续操作</a></p><p>如果这不是您本人操作，可以忽略此邮件。</p>",
	}, nil
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
