package humanverification

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

func NormalizeSettings(value Settings) (Settings, error) {
	value.Provider = strings.ToLower(strings.TrimSpace(value.Provider))
	value.SiteKey = strings.TrimSpace(value.SiteKey)
	value.WidgetMode = strings.ToLower(strings.TrimSpace(value.WidgetMode))
	if value.Provider != ProviderTurnstile {
		return Settings{}, fmt.Errorf("%w: unsupported provider %q", ErrInvalidConfig, value.Provider)
	}
	if !validBoundedPlainText(value.SiteKey, 1, 256) {
		return Settings{}, fmt.Errorf("%w: site key must contain 1 to 256 safe characters", ErrInvalidConfig)
	}
	switch value.WidgetMode {
	case WidgetManaged, WidgetNonInteractive, WidgetInvisible:
	default:
		return Settings{}, fmt.Errorf("%w: unsupported widget mode %q", ErrInvalidConfig, value.WidgetMode)
	}
	return value, nil
}

func ValidateSecret(secret string) error {
	if !validBoundedPlainText(secret, 1, 4096) {
		return fmt.Errorf("%w: secret must contain 1 to 4096 safe characters", ErrInvalidConfig)
	}
	return nil
}

func NormalizeRecoveryReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	if !validBoundedPlainText(reason, 3, 500) {
		return "", fmt.Errorf("disable reason must contain 3 to 500 safe characters")
	}
	return reason, nil
}

func NormalizePolicy(value Policy) (Policy, error) {
	value.LoginMode = strings.ToLower(strings.TrimSpace(value.LoginMode))
	switch value.LoginMode {
	case LoginOff, LoginAdaptive, LoginAlways:
	default:
		return Policy{}, fmt.Errorf("%w: unsupported login mode %q", ErrInvalidConfig, value.LoginMode)
	}
	if value.LoginTriggerAfter < 1 || value.LoginTriggerAfter > 100 {
		return Policy{}, fmt.Errorf("%w: login trigger must be between 1 and 100 attempts", ErrInvalidConfig)
	}
	return value, nil
}

func ValidAction(action string) bool {
	switch action {
	case ActionRegistration, ActionLogin, ActionPasswordReset,
		ActionEmailVerificationResend, ActionProviderLogin, ActionAdminTest:
		return true
	default:
		return false
	}
}

func PolicyRequires(policy Policy, action string, loginAttempt int) bool {
	switch action {
	case ActionRegistration:
		return policy.Registration
	case ActionPasswordReset:
		return policy.PasswordReset
	case ActionEmailVerificationResend:
		return policy.EmailVerificationResend
	case ActionProviderLogin:
		return policy.ProviderLogin
	case ActionLogin:
		switch policy.LoginMode {
		case LoginAlways:
			return true
		case LoginAdaptive:
			return loginAttempt >= policy.LoginTriggerAfter
		}
	}
	return false
}

func validBoundedPlainText(value string, minRunes, maxRunes int) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return false
	}
	count := utf8.RuneCountInString(value)
	if count < minRunes || count > maxRunes {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '\u202a' || r == '\u202b' || r == '\u202c' || r == '\u202d' || r == '\u202e' || r == '\u2066' || r == '\u2067' || r == '\u2068' || r == '\u2069' {
			return false
		}
	}
	return true
}
