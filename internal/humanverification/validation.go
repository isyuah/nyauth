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

type policyRequirement uint8

const (
	requirementNone policyRequirement = iota
	requirementRegistration
	requirementLogin
	requirementPasswordReset
	requirementEmailVerificationResend
	requirementProviderLogin
)

type actionDefinition struct {
	external    string
	public      bool
	requirement policyRequirement
}

var actionDefinitions = [...]actionDefinition{
	ActionRegistration:            {external: "register", public: true, requirement: requirementRegistration},
	ActionLogin:                   {external: "login", public: true, requirement: requirementLogin},
	ActionPasswordReset:           {external: "password_reset", public: true, requirement: requirementPasswordReset},
	ActionEmailVerificationResend: {external: "email_verification_resend", public: true, requirement: requirementEmailVerificationResend},
	ActionProviderLogin:           {external: "provider_login", public: true, requirement: requirementProviderLogin},
	ActionAdminTest:               {external: "admin_test", public: false, requirement: requirementNone},
}

func (action Action) String() string {
	definition, ok := actionDefinitionFor(action)
	if !ok {
		return ""
	}
	return definition.external
}

func ValidAction(action Action) bool {
	_, ok := actionDefinitionFor(action)
	return ok
}

func ParseAction(value string) (Action, bool) {
	for action := ActionRegistration; action <= ActionAdminTest; action++ {
		if action.String() == value {
			return action, true
		}
	}
	return 0, false
}

func ParsePublicAction(value string) (Action, bool) {
	action, ok := ParseAction(value)
	if !ok {
		return 0, false
	}
	definition, _ := actionDefinitionFor(action)
	return action, definition.public
}

func AllActions() []Action {
	actions := make([]Action, 0, len(actionDefinitions)-1)
	for action := ActionRegistration; action <= ActionAdminTest; action++ {
		actions = append(actions, action)
	}
	return actions
}

func PolicyRequires(policy Policy, action Action, loginAttempt int) bool {
	definition, ok := actionDefinitionFor(action)
	if !ok {
		return false
	}
	switch definition.requirement {
	case requirementRegistration:
		return policy.Registration
	case requirementPasswordReset:
		return policy.PasswordReset
	case requirementEmailVerificationResend:
		return policy.EmailVerificationResend
	case requirementProviderLogin:
		return policy.ProviderLogin
	case requirementLogin:
		switch policy.LoginMode {
		case LoginAlways:
			return true
		case LoginAdaptive:
			return loginAttempt >= policy.LoginTriggerAfter
		}
	}
	return false
}

func actionDefinitionFor(action Action) (actionDefinition, bool) {
	if action <= 0 || int(action) >= len(actionDefinitions) {
		return actionDefinition{}, false
	}
	definition := actionDefinitions[action]
	return definition, definition.external != ""
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
