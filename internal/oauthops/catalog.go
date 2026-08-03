package oauthops

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nyasharp/nyauth/pkg/models"
)

type Flow string

const (
	FlowAuthorizationCode   Flow = "authorization_code"
	FlowClientCredentials   Flow = "client_credentials"
	FlowRefreshToken        Flow = "refresh_token"
	FlowDeviceAuthorization Flow = "device_authorization"
)

type Stage string

const (
	StageAuthorization       Stage = "authorization"
	StageConsent             Stage = "consent"
	StageToken               Stage = "token"
	StageDeviceAuthorization Stage = "device_authorization"
	StageDeviceVerification  Stage = "device_verification"
)

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
)

type Reason string

const (
	ReasonNone                      Reason = ""
	ReasonInvalidRequest            Reason = "invalid_request"
	ReasonInvalidClient             Reason = "invalid_client"
	ReasonRedirectURIMismatch       Reason = "redirect_uri_mismatch"
	ReasonInvalidState              Reason = "invalid_state"
	ReasonGrantNotAllowed           Reason = "grant_not_allowed"
	ReasonInvalidScope              Reason = "invalid_scope"
	ReasonInvalidPKCE               Reason = "invalid_pkce"
	ReasonInvalidNonce              Reason = "invalid_nonce"
	ReasonAccessDenied              Reason = "access_denied"
	ReasonClientChanged             Reason = "client_changed"
	ReasonInvalidScopeSelection     Reason = "invalid_scope_selection"
	ReasonInvalidOrExpiredCode      Reason = "invalid_or_expired_code"
	ReasonCodeBindingValidation     Reason = "code_binding_validation"
	ReasonScopeNoLongerAllowed      Reason = "scope_no_longer_allowed"
	ReasonClaimNoLongerAllowed      Reason = "claim_no_longer_allowed"
	ReasonInvalidSubject            Reason = "invalid_subject"
	ReasonInactiveSubject           Reason = "inactive_subject"
	ReasonAuthorizationInactive     Reason = "authorization_inactive"
	ReasonTokenIssuanceFailed       Reason = "token_issuance_failed"
	ReasonIDTokenIssuanceFailed     Reason = "id_token_issuance_failed"
	ReasonCodeReuse                 Reason = "code_reuse"
	ReasonCodeReuseRevocationFailed Reason = "code_reuse_revocation_failed"
	ReasonInvalidRefresh            Reason = "invalid_refresh"
	ReasonRefreshReuse              Reason = "refresh_reuse"
	ReasonAuthorizationPending      Reason = "authorization_pending"
	ReasonSlowDown                  Reason = "slow_down"
	ReasonExpiredToken              Reason = "expired_token"
	ReasonUserDenied                Reason = "user_denied"
	ReasonServicePaused             Reason = "service_paused"
	ReasonRateLimited               Reason = "rate_limited"
	ReasonTemporarilyUnavailable    Reason = "temporarily_unavailable"
	ReasonServerError               Reason = "server_error"
)

var validFlows = map[Flow]struct{}{
	FlowAuthorizationCode: {}, FlowClientCredentials: {}, FlowRefreshToken: {}, FlowDeviceAuthorization: {},
}

var validStages = map[Stage]struct{}{
	StageAuthorization: {}, StageConsent: {}, StageToken: {}, StageDeviceAuthorization: {}, StageDeviceVerification: {},
}

var validReasons = map[Reason]struct{}{
	ReasonInvalidRequest: {}, ReasonInvalidClient: {}, ReasonRedirectURIMismatch: {}, ReasonInvalidState: {},
	ReasonGrantNotAllowed: {}, ReasonInvalidScope: {}, ReasonInvalidPKCE: {}, ReasonInvalidNonce: {},
	ReasonAccessDenied: {}, ReasonClientChanged: {}, ReasonInvalidScopeSelection: {}, ReasonInvalidOrExpiredCode: {},
	ReasonCodeBindingValidation: {}, ReasonScopeNoLongerAllowed: {}, ReasonClaimNoLongerAllowed: {},
	ReasonInvalidSubject: {}, ReasonInactiveSubject: {}, ReasonAuthorizationInactive: {}, ReasonTokenIssuanceFailed: {},
	ReasonIDTokenIssuanceFailed: {}, ReasonCodeReuse: {}, ReasonCodeReuseRevocationFailed: {}, ReasonInvalidRefresh: {},
	ReasonRefreshReuse: {}, ReasonAuthorizationPending: {}, ReasonSlowDown: {}, ReasonExpiredToken: {},
	ReasonUserDenied: {}, ReasonServicePaused: {}, ReasonRateLimited: {}, ReasonTemporarilyUnavailable: {}, ReasonServerError: {},
}

type Event struct {
	ClientID    string
	Flow        Flow
	Stage       Stage
	Outcome     Outcome
	Reason      Reason
	RequestID   string
	RedirectURI string
	Scopes      []string
	OccurredAt  time.Time
}

func (event *Event) Normalize() error {
	event.ClientID = strings.TrimSpace(event.ClientID)
	event.RequestID = strings.TrimSpace(event.RequestID)
	event.RedirectURI = sanitizeRedirectURI(event.RedirectURI)
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	} else {
		event.OccurredAt = event.OccurredAt.UTC()
	}
	if event.ClientID == "" || len(event.ClientID) > 64 {
		return errors.New("OAuth operation client ID is invalid")
	}
	if _, ok := validFlows[event.Flow]; !ok {
		return fmt.Errorf("unknown OAuth operation flow %q", event.Flow)
	}
	if _, ok := validStages[event.Stage]; !ok {
		return fmt.Errorf("unknown OAuth operation stage %q", event.Stage)
	}
	if event.Outcome != OutcomeSuccess && event.Outcome != OutcomeFailure {
		return fmt.Errorf("unknown OAuth operation outcome %q", event.Outcome)
	}
	if event.Outcome == OutcomeSuccess {
		event.Reason = ReasonNone
	} else if _, ok := validReasons[event.Reason]; !ok {
		return fmt.Errorf("unknown OAuth operation reason %q", event.Reason)
	}
	if len(event.RequestID) > 128 {
		event.RequestID = event.RequestID[:128]
	}
	event.Scopes = canonicalScopes(event.Scopes)
	return nil
}

func FlowForGrant(grant string) (Flow, bool) {
	switch strings.TrimSpace(grant) {
	case models.GrantAuthorizationCode:
		return FlowAuthorizationCode, true
	case models.GrantClientCredentials:
		return FlowClientCredentials, true
	case models.GrantRefreshToken:
		return FlowRefreshToken, true
	case models.GrantDeviceCode:
		return FlowDeviceAuthorization, true
	default:
		return "", false
	}
}

func ReasonForGrantFailure(value string) Reason {
	switch strings.TrimSpace(value) {
	case "invalid_form", "missing_code", "missing_token":
		return ReasonInvalidRequest
	case "invalid_client":
		return ReasonInvalidClient
	case "grant_not_allowed":
		return ReasonGrantNotAllowed
	case "invalid_scope":
		return ReasonInvalidScope
	case "invalid_or_expired_code":
		return ReasonInvalidOrExpiredCode
	case "code_binding_validation":
		return ReasonCodeBindingValidation
	case "scope_no_longer_allowed":
		return ReasonScopeNoLongerAllowed
	case "claim_no_longer_allowed":
		return ReasonClaimNoLongerAllowed
	case "invalid_subject":
		return ReasonInvalidSubject
	case "inactive_subject":
		return ReasonInactiveSubject
	case "authorization_inactive":
		return ReasonAuthorizationInactive
	case "token_issuance_failed":
		return ReasonTokenIssuanceFailed
	case "id_token_issuance_failed":
		return ReasonIDTokenIssuanceFailed
	case "code_reuse":
		return ReasonCodeReuse
	case "code_reuse_revocation_failed":
		return ReasonCodeReuseRevocationFailed
	case "invalid_refresh":
		return ReasonInvalidRefresh
	case "refresh_reuse":
		return ReasonRefreshReuse
	case "authorization_pending":
		return ReasonAuthorizationPending
	case "slow_down":
		return ReasonSlowDown
	case "expired_token":
		return ReasonExpiredToken
	case "access_denied":
		return ReasonUserDenied
	case "service_paused":
		return ReasonServicePaused
	case "rate_limited":
		return ReasonRateLimited
	case "temporarily_unavailable", "authorization_code_store_unavailable":
		return ReasonTemporarilyUnavailable
	default:
		return ReasonServerError
	}
}

func ValidFlow(value string) bool   { _, ok := validFlows[Flow(value)]; return ok }
func ValidStage(value string) bool  { _, ok := validStages[Stage(value)]; return ok }
func ValidReason(value string) bool { _, ok := validReasons[Reason(value)]; return ok }

func sanitizeRedirectURI(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return ""
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	result := parsed.String()
	if len(result) > 2048 {
		return ""
	}
	return result
}

func canonicalScopes(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !models.ValidOAuthScope(value) {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
