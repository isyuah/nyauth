package humanverification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

const turnstileSiteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

type Verifier interface {
	Verify(context.Context, VerifyInput) (VerifyResult, error)
}

type TurnstileOptions struct {
	Secret           string
	ExpectedHostname string
	Client           *http.Client
	Endpoint         string
}

type TurnstileVerifier struct {
	secret           string
	expectedHostname string
	client           *http.Client
	endpoint         string
}

type turnstileResponse struct {
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
	ErrorCodes []string `json:"error-codes"`
}

func NewTurnstileVerifier(options TurnstileOptions) (*TurnstileVerifier, error) {
	if err := ValidateSecret(options.Secret); err != nil {
		return nil, err
	}
	hostname := strings.ToLower(strings.TrimSpace(options.ExpectedHostname))
	if hostname == "" || strings.ContainsAny(hostname, "/\\:@") {
		return nil, fmt.Errorf("%w: expected hostname is invalid", ErrInvalidConfig)
	}
	client := options.Client
	if client == nil {
		client = &http.Client{
			Timeout: DefaultRequestTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	endpoint := strings.TrimSpace(options.Endpoint)
	if endpoint == "" {
		endpoint = turnstileSiteverifyURL
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%w: siteverify endpoint is invalid", ErrInvalidConfig)
	}
	return &TurnstileVerifier{secret: options.Secret, expectedHostname: hostname, client: client, endpoint: endpoint}, nil
}

func (v *TurnstileVerifier) Verify(ctx context.Context, input VerifyInput) (VerifyResult, error) {
	token := strings.TrimSpace(input.Token)
	if token == "" || len(token) > 4096 || !ValidAction(input.Action) {
		return VerifyResult{}, ErrVerificationRejected
	}
	if _, err := uuid.Parse(input.IdempotencyKey); err != nil {
		return VerifyResult{}, ErrVerificationRejected
	}
	values := url.Values{
		"secret":          {v.secret},
		"response":        {token},
		"idempotency_key": {input.IdempotencyKey},
	}
	if remoteIP := strings.TrimSpace(input.RemoteIP); remoteIP != "" {
		values.Set("remoteip", remoteIP)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return VerifyResult{}, fmt.Errorf("%w: creating siteverify request", ErrVerificationUnavailable)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := v.client.Do(request)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return VerifyResult{}, err
		}
		return VerifyResult{}, fmt.Errorf("%w: requesting siteverify", ErrVerificationUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return VerifyResult{}, fmt.Errorf("%w: siteverify returned HTTP %d", ErrVerificationUnavailable, response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	var decoded turnstileResponse
	if err := decoder.Decode(&decoded); err != nil {
		return VerifyResult{}, fmt.Errorf("%w: decoding siteverify response", ErrVerificationUnavailable)
	}
	result := VerifyResult{
		Hostname:   strings.ToLower(strings.TrimSpace(decoded.Hostname)),
		Action:     strings.TrimSpace(decoded.Action),
		ErrorCodes: boundedErrorCodes(decoded.ErrorCodes),
	}
	if !decoded.Success {
		if containsConfigurationError(result.ErrorCodes) {
			return result, ErrVerificationUnavailable
		}
		return result, ErrVerificationRejected
	}
	if result.Hostname != v.expectedHostname || result.Action != input.Action.String() {
		return result, ErrVerificationRejected
	}
	return result, nil
}

func boundedErrorCodes(values []string) []string {
	result := make([]string, 0, min(len(values), 10))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 64 {
			continue
		}
		result = append(result, value)
		if len(result) == 10 {
			break
		}
	}
	return result
}

func containsConfigurationError(codes []string) bool {
	for _, code := range codes {
		switch code {
		case "missing-input-secret", "invalid-input-secret", "bad-request", "internal-error":
			return true
		}
	}
	return false
}

func VerificationErrorCode(err error, result VerifyResult) string {
	if errors.Is(err, ErrVerificationRejected) {
		if len(result.ErrorCodes) > 0 {
			return result.ErrorCodes[0]
		}
		return "rejected"
	}
	if errors.Is(err, ErrVerificationUnavailable) {
		if len(result.ErrorCodes) > 0 {
			return result.ErrorCodes[0]
		}
		return "unavailable"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "unknown"
}

var _ Verifier = (*TurnstileVerifier)(nil)
