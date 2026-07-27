package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/auth"
	"github.com/nyasharp/nyauth/internal/config"
	nyacrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/telemetry"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

const haIntegrationTimeout = 45 * time.Second

type haHTTPTestCluster struct {
	apps           [2]*Server
	httpServers    [2]*httptest.Server
	redisClients   [2]*redis.Client
	redisKeys      map[string]struct{}
	sessionMembers map[string]struct{}
}

type haLogin struct {
	cookie  *http.Cookie
	session models.SessionResponse
}

type haTokenHTTPResult struct {
	status int
	body   []byte
	err    error
}

type haPasskeyFixture struct {
	credentialID []byte
	userHandle   []byte
	privateKey   *ecdsa.PrivateKey
}

func TestHAHTTPServersShareSessionAndAccountState(t *testing.T) {
	cluster := newHAHTTPTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), haIntegrationTimeout)
	defer cancel()

	marker := strings.ReplaceAll(uuid.NewString(), "-", "")
	const password = "ha-integration-password-123"
	target, err := cluster.apps[0].userService.Create(ctx, models.CreateUserRequest{
		Username: "ha_user_" + marker, Password: password, Metadata: map[string]string{},
	})
	if err != nil {
		t.Fatalf("create target user: %v", err)
	}
	admin, err := cluster.apps[0].userService.Create(ctx, models.CreateUserRequest{
		Username: "ha_admin_" + marker, Password: password, Metadata: map[string]string{},
	})
	if err != nil {
		t.Fatalf("create administrator: %v", err)
	}
	if _, err := cluster.apps[0].db.Exec(ctx, `UPDATE users SET role='admin' WHERE id=$1`, admin.ID); err != nil {
		t.Fatalf("promote integration administrator: %v", err)
	}

	targetIP := fmt.Sprintf("2001:db8:%s:%s::41", marker[:4], marker[4:8])
	targetLogin := cluster.login(t, 0, target.Username, password, targetIP)
	response := cluster.request(t, 1, http.MethodGet, "/api/session", nil, targetLogin.cookie, "", targetIP)
	if response.StatusCode != http.StatusOK {
		body := readHAResponse(t, response)
		t.Fatalf("load first-instance cookie through second instance: status=%d body=%s", response.StatusCode, body)
	}
	var crossInstanceSession models.SessionResponse
	decodeHAResponse(t, response, &crossInstanceSession)
	if crossInstanceSession.User == nil || crossInstanceSession.User.ID != target.ID || crossInstanceSession.CSRFToken != targetLogin.session.CSRFToken {
		t.Fatalf("second instance returned a different session: %#v", crossInstanceSession)
	}
	registered, err := cluster.apps[0].clientService.Create(ctx, models.CreateClientRequest{
		Name: "HA session revocation client", RedirectURIs: []string{"https://client.invalid/session/" + marker},
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"profile"}, IsPublic: true,
	})
	if err != nil {
		t.Fatalf("create session-revocation OAuth client: %v", err)
	}
	oauthClientID := registered.ID
	authorizationIssuedAt, err := cluster.apps[0].sessionStore.AuthorizationIssueTime(ctx, target.ID.String(), oauthClientID, time.Hour)
	if err != nil {
		t.Fatalf("create OAuth authorization clock: %v", err)
	}
	cluster.trackRedisKey("nyauth:authorization-clock:" + haDigest(target.ID.String()+"\x00"+oauthClientID))
	tokenPair, err := cluster.apps[0].tokenService.GenerateAuthorizationCodeTokenPair(
		ctx, oauthClientID, target.ID.String(), []string{"profile"}, target.AuthVersion, authorizationIssuedAt, false,
	)
	if err != nil {
		t.Fatalf("issue OAuth access token before browser-session revocation: %v", err)
	}
	tokenClaims := &auth.Claims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tokenPair.AccessToken, tokenClaims); err != nil || tokenClaims.ID == "" {
		t.Fatalf("parse access token metadata: jti=%q err=%v", tokenClaims.ID, err)
	}
	cluster.trackRedisKey("nyauth:token:" + haDigest(tokenClaims.ID))

	adminIP := fmt.Sprintf("2001:db8:%s:%s::42", marker[:4], marker[4:8])
	adminLogin := cluster.login(t, 1, admin.Username, password, adminIP)
	revokeSessionsPath := "/api/admin/users/" + target.ID.String() + "/sessions"
	response = cluster.request(t, 0, http.MethodDelete, revokeSessionsPath, nil, adminLogin.cookie, adminLogin.session.CSRFToken, adminIP)
	if response.StatusCode != http.StatusOK {
		body := readHAResponse(t, response)
		t.Fatalf("revoke user sessions through first instance: status=%d body=%s", response.StatusCode, body)
	}
	var revokeResult struct {
		Revoked int64 `json:"revoked"`
	}
	decodeHAResponse(t, response, &revokeResult)
	if revokeResult.Revoked != 1 {
		t.Fatalf("revoked session count = %d, want 1", revokeResult.Revoked)
	}
	afterRevocation, err := cluster.apps[1].userService.GetByID(ctx, target.ID)
	if err != nil {
		t.Fatalf("load target after session revocation: %v", err)
	}
	if afterRevocation.AuthVersion != target.AuthVersion || afterRevocation.SessionVersion != target.SessionVersion+1 {
		t.Fatalf("versions after session revocation = {auth:%d session:%d}, want {%d %d}",
			afterRevocation.AuthVersion, afterRevocation.SessionVersion, target.AuthVersion, target.SessionVersion+1)
	}
	if _, err := cluster.apps[1].tokenService.ValidateAccessToken(ctx, tokenPair.AccessToken); err != nil {
		t.Fatalf("browser-session revocation invalidated OAuth access token: %v", err)
	}
	var successAuditPayload []byte
	if err := cluster.apps[1].db.QueryRow(ctx, `
		SELECT payload FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='user' AND aggregate_id=$2 AND payload->>'result'='success'
		ORDER BY created_at DESC LIMIT 1
	`, models.AuditUserSessionsRevoked, target.ID.String()).Scan(&successAuditPayload); err != nil {
		t.Fatalf("load transactional session revocation audit: %v", err)
	}
	var successAudit map[string]any
	if err := json.Unmarshal(successAuditPayload, &successAudit); err != nil {
		t.Fatalf("decode transactional session revocation audit: %v", err)
	}
	successDetails, _ := successAudit["details"].(map[string]any)
	if successAudit["actor_id"] != admin.ID.String() || successAudit["target_id"] != target.ID.String() ||
		successAudit["risk_level"] != "high" || successDetails["session_version"] != float64(target.SessionVersion+1) {
		t.Fatalf("unexpected transactional session revocation audit: %#v", successAudit)
	}

	response = cluster.request(t, 1, http.MethodGet, "/api/session", nil, targetLogin.cookie, "", targetIP)
	if response.StatusCode != http.StatusUnauthorized {
		body := readHAResponse(t, response)
		t.Fatalf("revoked user session on second instance: status=%d body=%s", response.StatusCode, body)
	}
	if !responseClearsCookie(response, sessionCookieName) {
		body := readHAResponse(t, response)
		t.Fatalf("second instance did not clear revoked session cookie: body=%s", body)
	}
	_ = readHAResponse(t, response)

	missingID := uuid.New()
	missingPath := "/api/admin/users/" + missingID.String() + "/sessions"
	response = cluster.request(t, 1, http.MethodDelete, missingPath, nil, adminLogin.cookie, adminLogin.session.CSRFToken, adminIP)
	if response.StatusCode != http.StatusNotFound {
		body := readHAResponse(t, response)
		t.Fatalf("missing-user session revocation: status=%d body=%s", response.StatusCode, body)
	}
	_ = readHAResponse(t, response)
	var failureEvent string
	if err := cluster.apps[0].db.QueryRow(ctx, `
		SELECT event FROM audit_event_outbox
		WHERE aggregate_type='user' AND aggregate_id=$1 AND payload->>'result'='failure'
		ORDER BY created_at DESC LIMIT 1
	`, missingID.String()).Scan(&failureEvent); err != nil {
		t.Fatalf("load missing-user revocation failure audit: %v", err)
	}
	if failureEvent != models.AuditUserSessionsRevoked {
		t.Fatalf("missing-user failure audit event=%q, want %q", failureEvent, models.AuditUserSessionsRevoked)
	}

	targetLogin = cluster.login(t, 0, target.Username, password, targetIP)
	response = cluster.request(t, 1, http.MethodGet, "/api/session", nil, targetLogin.cookie, "", targetIP)
	if response.StatusCode != http.StatusOK {
		body := readHAResponse(t, response)
		t.Fatalf("load renewed first-instance cookie through second instance: status=%d body=%s", response.StatusCode, body)
	}
	_ = readHAResponse(t, response)

	suspendPath := "/api/admin/users/" + target.ID.String() + "/suspend"
	response = cluster.request(t, 0, http.MethodPost, suspendPath, nil, adminLogin.cookie, adminLogin.session.CSRFToken, adminIP)
	if response.StatusCode != http.StatusOK {
		body := readHAResponse(t, response)
		t.Fatalf("suspend user through first instance: status=%d body=%s", response.StatusCode, body)
	}
	_ = readHAResponse(t, response)

	updated, err := cluster.apps[1].userService.GetByID(ctx, target.ID)
	if err != nil {
		t.Fatalf("load suspended user through second instance: %v", err)
	}
	if updated.Status != models.UserStatusSuspended || updated.AuthVersion != target.AuthVersion+1 {
		t.Fatalf("shared account state = {status:%q auth_version:%d}, want {suspended %d}", updated.Status, updated.AuthVersion, target.AuthVersion+1)
	}

	response = cluster.request(t, 1, http.MethodGet, "/api/session", nil, targetLogin.cookie, "", targetIP)
	if response.StatusCode != http.StatusUnauthorized {
		body := readHAResponse(t, response)
		t.Fatalf("suspended user's session on second instance: status=%d body=%s", response.StatusCode, body)
	}
	if !responseClearsCookie(response, sessionCookieName) {
		body := readHAResponse(t, response)
		t.Fatalf("second instance did not clear invalidated session cookie: body=%s", body)
	}
	_ = readHAResponse(t, response)

	response = cluster.request(t, 0, http.MethodPost, "/api/logout", nil, adminLogin.cookie, adminLogin.session.CSRFToken, adminIP)
	if response.StatusCode != http.StatusNoContent {
		body := readHAResponse(t, response)
		t.Fatalf("logout administrator through other instance: status=%d body=%s", response.StatusCode, body)
	}
	_ = readHAResponse(t, response)
}

func TestHAHTTPServersFinishPasskeyLoginAcrossInstances(t *testing.T) {
	cluster := newHAHTTPTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), haIntegrationTimeout)
	defer cancel()

	marker := strings.ReplaceAll(uuid.NewString(), "-", "")
	current, err := cluster.apps[0].userService.Create(ctx, models.CreateUserRequest{
		Username: "ha_passkey_" + marker, Password: "ha-passkey-password-123", Metadata: map[string]string{},
	})
	if err != nil {
		t.Fatalf("create Passkey user: %v", err)
	}
	fixture := insertHAPasskeyFixture(t, ctx, cluster.apps[0].db, current.ID)
	ip := fmt.Sprintf("2001:db8:%s:%s::71", marker[:4], marker[4:8])
	cluster.trackRedisKey("nyauth:passkey-ceremony-limit:ip:" + limitDigest(ip))
	cluster.trackRedisKey("nyauth:login-limit:ip:" + limitDigest(ip))

	optionsResponse := cluster.request(
		t, 0, http.MethodPost, "/api/login/passkey/options",
		strings.NewReader(`{"conditional":false,"return_to":"/profile"}`), nil, "", ip,
	)
	if optionsResponse.StatusCode != http.StatusOK {
		body := readHAResponse(t, optionsResponse)
		t.Fatalf("begin Passkey login through first instance: status=%d body=%s", optionsResponse.StatusCode, body)
	}
	var options struct {
		CeremonyID string                                     `json:"ceremony_id"`
		PublicKey  protocol.PublicKeyCredentialRequestOptions `json:"public_key"`
	}
	decodeHAResponse(t, optionsResponse, &options)
	if options.CeremonyID == "" || options.PublicKey.Challenge.String() == "" {
		t.Fatalf("first instance returned incomplete Passkey options: %#v", options)
	}
	cluster.trackRedisKey("nyauth:webauthn-ceremony:" + haDigest(options.CeremonyID))
	payload := haPasskeyAssertionPayload(t, options.PublicKey, fixture, 1)

	verified := cluster.passkeyRequest(
		t, 1, "/api/login/passkey/verify", payload, options.CeremonyID, ip,
	)
	if verified.StatusCode != http.StatusOK {
		body := readHAResponse(t, verified)
		t.Fatalf("finish Passkey login through second instance: status=%d body=%s", verified.StatusCode, body)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range verified.Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly {
		_ = readHAResponse(t, verified)
		t.Fatalf("Passkey login response is missing an HttpOnly session cookie: %#v", sessionCookie)
	}
	var authenticated models.SessionResponse
	decodeHAResponse(t, verified, &authenticated)
	if authenticated.User == nil || authenticated.User.ID != current.ID || authenticated.CSRFToken == "" {
		t.Fatalf("unexpected Passkey login session: %#v", authenticated)
	}
	sessionKey := "nyauth:session:" + haDigest(sessionCookie.Value)
	cluster.trackRedisKey(sessionKey)
	cluster.sessionMembers[sessionKey] = struct{}{}
	cluster.trackRedisKey("nyauth:user-sessions:" + haDigest(current.ID.String()))

	replayed := cluster.passkeyRequest(
		t, 0, "/api/login/passkey/verify", payload, options.CeremonyID, ip,
	)
	if replayed.StatusCode != http.StatusUnauthorized {
		body := readHAResponse(t, replayed)
		t.Fatalf("replay consumed Passkey ceremony: status=%d body=%s", replayed.StatusCode, body)
	}
	_ = readHAResponse(t, replayed)

	var signCount int64
	var passkeyAuditCount int
	if err := cluster.apps[1].db.QueryRow(ctx, `
		SELECT credential.sign_count,
		       (SELECT COUNT(*) FROM audit_event_outbox
		        WHERE event=$2 AND aggregate_id=credential.id::text)
		FROM user_passkey_credentials AS credential
		WHERE credential.rp_id=$1 AND credential.credential_id=$3
	`, "nyauth-ha.invalid", models.AuditPasskeyLogin, fixture.credentialID).Scan(
		&signCount, &passkeyAuditCount,
	); err != nil {
		t.Fatalf("load cross-instance Passkey state: %v", err)
	}
	if signCount != 1 || passkeyAuditCount != 1 {
		t.Fatalf("cross-instance Passkey state: sign_count=%d audits=%d", signCount, passkeyAuditCount)
	}
}

func TestHAHTTPServersConsumeAuthorizationCodeOnce(t *testing.T) {
	cluster := newHAHTTPTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), haIntegrationTimeout)
	defer cancel()

	marker := strings.ReplaceAll(uuid.NewString(), "-", "")
	current, err := cluster.apps[0].userService.Create(ctx, models.CreateUserRequest{
		Username: "ha_token_" + marker, Password: "ha-token-password-123", Metadata: map[string]string{},
	})
	if err != nil {
		t.Fatalf("create authorization subject: %v", err)
	}
	redirectURI := "https://client.invalid/callback/" + marker
	registered, err := cluster.apps[0].clientService.Create(ctx, models.CreateClientRequest{
		Name: "HA integration client", RedirectURIs: []string{redirectURI},
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"profile"}, IsPublic: true,
	})
	if err != nil {
		t.Fatalf("create public OAuth client: %v", err)
	}

	verifier := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	challengeDigest := sha256.Sum256([]byte(verifier))
	code := "ha-code-" + marker
	stored := &session.AuthorizationData{
		ClientID: registered.ID, UserID: current.ID.String(), RedirectURI: redirectURI,
		Scopes: []string{"profile"}, CodeChallenge: base64.RawURLEncoding.EncodeToString(challengeDigest[:]),
		ChallengeMethod: "S256", AuthVersion: current.AuthVersion, AuthorizationIssuedAt: time.Now().UTC().UnixMicro(),
	}
	if err := cluster.apps[0].sessionStore.SaveAuthorizationCode(ctx, code, stored, time.Minute); err != nil {
		t.Fatalf("store authorization code through first instance: %v", err)
	}
	cluster.trackRedisKey("nyauth:code:" + haDigest(code))

	type tokenResult struct {
		status int
		body   []byte
		err    error
	}
	start := make(chan struct{})
	results := make(chan tokenResult, 2)
	var workers sync.WaitGroup
	for index := range 2 {
		workers.Add(1)
		go func(instance int) {
			defer workers.Done()
			<-start
			form := url.Values{
				"grant_type":    {models.GrantAuthorizationCode},
				"client_id":     {registered.ID},
				"code":          {code},
				"redirect_uri":  {redirectURI},
				"code_verifier": {verifier},
			}
			request, requestErr := http.NewRequest(http.MethodPost, cluster.httpServers[instance].URL+"/token", strings.NewReader(form.Encode()))
			if requestErr != nil {
				results <- tokenResult{err: requestErr}
				return
			}
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response, requestErr := cluster.httpServers[instance].Client().Do(request)
			if requestErr != nil {
				results <- tokenResult{err: requestErr}
				return
			}
			defer response.Body.Close()
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			results <- tokenResult{status: response.StatusCode, body: body, err: readErr}
		}(index)
	}
	close(start)
	workers.Wait()
	close(results)

	successes := 0
	invalidGrants := 0
	var tokenPair auth.TokenPair
	for result := range results {
		if result.err != nil {
			t.Fatalf("exchange authorization code: %v", result.err)
		}
		switch result.status {
		case http.StatusOK:
			successes++
			if err := json.Unmarshal(result.body, &tokenPair); err != nil {
				t.Fatalf("decode successful token response: %v; body=%s", err, result.body)
			}
		case http.StatusBadRequest:
			var payload struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(result.body, &payload); err != nil || payload.Error != "invalid_grant" {
				t.Fatalf("unexpected failed token response: status=%d body=%s", result.status, result.body)
			}
			invalidGrants++
		default:
			t.Fatalf("unexpected token response: status=%d body=%s", result.status, result.body)
		}
	}
	if successes != 1 || invalidGrants != 1 || tokenPair.AccessToken == "" {
		t.Fatalf("authorization-code outcomes: success=%d invalid_grant=%d access_token_present=%v", successes, invalidGrants, tokenPair.AccessToken != "")
	}

	claims := &auth.Claims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tokenPair.AccessToken, claims); err != nil || claims.ID == "" {
		t.Fatalf("parse issued access token metadata: jti=%q err=%v", claims.ID, err)
	}
	accessKey := "nyauth:token:" + haDigest(claims.ID)
	cluster.trackRedisKey(accessKey)

	otherClient, err := cluster.apps[0].clientService.Create(ctx, models.CreateClientRequest{
		Name: "HA non-owner client", RedirectURIs: []string{"https://client.invalid/other/" + marker},
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"profile"}, IsPublic: true,
	})
	if err != nil {
		t.Fatalf("create non-owner OAuth client: %v", err)
	}
	mismatchForm := url.Values{"client_id": {otherClient.ID}, "token": {tokenPair.AccessToken}}
	response := cluster.request(t, 1, http.MethodPost, "/revoke", strings.NewReader(mismatchForm.Encode()), nil, "", "")
	if response.StatusCode != http.StatusOK {
		body := readHAResponse(t, response)
		t.Fatalf("cross-client revocation response: status=%d body=%s", response.StatusCode, body)
	}
	_ = readHAResponse(t, response)
	if exists, err := cluster.redisClients[0].Exists(ctx, accessKey).Result(); err != nil || exists != 1 {
		t.Fatalf("cross-client revocation mutated access metadata: exists=%d err=%v", exists, err)
	}
	mismatchAudit, mismatchPayload := cluster.auditPayload(t, models.AuditTokenRevoked, otherClient.ID, "failure")
	if mismatchAudit["actor_name"] != otherClient.ID || mismatchAudit["target_type"] != "client" || mismatchAudit["target_id"] != otherClient.ID {
		t.Fatalf("cross-client revocation audit identity: %#v", mismatchAudit)
	}
	mismatchDetails, _ := mismatchAudit["details"].(map[string]any)
	if mismatchDetails["failure_reason"] != "client_binding_mismatch" {
		t.Fatalf("cross-client revocation audit details: %#v", mismatchDetails)
	}
	if bytes.Contains(mismatchPayload, []byte(tokenPair.AccessToken)) {
		t.Fatal("cross-client revocation audit persisted the access token")
	}

	revokeForm := url.Values{"client_id": {registered.ID}, "token": {tokenPair.AccessToken}}
	response = cluster.request(t, 1, http.MethodPost, "/revoke", strings.NewReader(revokeForm.Encode()), nil, "", "")
	if response.StatusCode != http.StatusOK {
		body := readHAResponse(t, response)
		t.Fatalf("revoke first-instance token through second instance: status=%d body=%s", response.StatusCode, body)
	}
	_ = readHAResponse(t, response)
	if exists, err := cluster.redisClients[0].Exists(ctx, accessKey).Result(); err != nil || exists != 0 {
		t.Fatalf("revoked access metadata still exists: exists=%d err=%v", exists, err)
	}
	successAudit, successPayload := cluster.auditPayload(t, models.AuditTokenRevoked, registered.ID, "success")
	if successAudit["actor_name"] != registered.ID || successAudit["target_type"] != "client" || successAudit["target_id"] != registered.ID {
		t.Fatalf("successful revocation audit identity: %#v", successAudit)
	}
	if bytes.Contains(successPayload, []byte(tokenPair.AccessToken)) || bytes.Contains(successPayload, []byte(code)) {
		t.Fatal("successful revocation audit persisted an OAuth credential")
	}
}

func TestHAHTTPEndSessionWritesAuditOutbox(t *testing.T) {
	cluster := newHAHTTPTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), haIntegrationTimeout)
	defer cancel()

	marker := strings.ReplaceAll(uuid.NewString(), "-", "")
	current, err := cluster.apps[0].userService.Create(ctx, models.CreateUserRequest{
		Username: "ha_logout_" + marker, Password: "ha-logout-password-123", Metadata: map[string]string{},
	})
	if err != nil {
		t.Fatalf("create logout subject: %v", err)
	}
	registered, err := cluster.apps[0].clientService.Create(ctx, models.CreateClientRequest{
		Name: "HA logout client", RedirectURIs: []string{"https://client.invalid/callback/" + marker},
		PostLogoutRedirectURIs: []string{"https://client.invalid/logout/" + marker},
		Grants:                 []string{models.GrantAuthorizationCode}, Scopes: []string{"openid"}, IsPublic: true,
	})
	if err != nil {
		t.Fatalf("create logout OAuth client: %v", err)
	}

	login := cluster.login(t, 0, current.Username, "ha-logout-password-123", "2001:db8::51")
	nonce := "ha-end-session-nonce-" + marker
	idToken, err := cluster.apps[0].tokenService.GenerateIDToken(ctx, registered.ID, current.ID.String(), []string{"openid"}, nonce, nil)
	if err != nil {
		t.Fatalf("generate ID token: %v", err)
	}
	response := cluster.request(t, 1, http.MethodGet, "/end_session?id_token_hint="+url.QueryEscape(idToken), nil, login.cookie, "", "2001:db8::51")
	if response.StatusCode != http.StatusOK {
		body := readHAResponse(t, response)
		t.Fatalf("end session through second instance: status=%d body=%s", response.StatusCode, body)
	}
	_ = readHAResponse(t, response)

	response = cluster.request(t, 0, http.MethodGet, "/api/session", nil, login.cookie, "", "2001:db8::51")
	if response.StatusCode != http.StatusUnauthorized {
		body := readHAResponse(t, response)
		t.Fatalf("ended session remained usable on first instance: status=%d body=%s", response.StatusCode, body)
	}
	_ = readHAResponse(t, response)

	payload, rawPayload := cluster.auditPayload(t, models.AuditUserLogout, registered.ID, "success")
	if payload["actor_id"] != current.ID.String() || payload["actor_name"] != current.Username ||
		payload["target_type"] != "client" || payload["target_id"] != registered.ID {
		t.Fatalf("end-session audit identity: %#v", payload)
	}
	for name, secret := range map[string]string{"ID token": idToken, "session cookie": login.cookie.Value, "nonce": nonce} {
		if bytes.Contains(rawPayload, []byte(secret)) {
			t.Fatalf("end-session audit persisted %s", name)
		}
	}

	response = cluster.request(t, 1, http.MethodGet, "/end_session?id_token_hint="+url.QueryEscape(idToken), nil, nil, "", "2001:db8::51")
	if response.StatusCode != http.StatusOK {
		body := readHAResponse(t, response)
		t.Fatalf("idempotent end session without cookie: status=%d body=%s", response.StatusCode, body)
	}
	_ = readHAResponse(t, response)
	noSessionAudit, _ := cluster.auditPayload(t, models.AuditUserLogout, registered.ID, "failure")
	details, _ := noSessionAudit["details"].(map[string]any)
	if noSessionAudit["actor_id"] != nil || noSessionAudit["actor_name"] != nil || details["failure_reason"] != "no_active_session" {
		t.Fatalf("end-session no-op was audited as a user logout: %#v", noSessionAudit)
	}
}

func TestHAHTTPServersRotateRefreshTokenOnceAndRevokeReusedFamily(t *testing.T) {
	cluster := newHAHTTPTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), haIntegrationTimeout)
	defer cancel()

	marker := strings.ReplaceAll(uuid.NewString(), "-", "")
	current, err := cluster.apps[0].userService.Create(ctx, models.CreateUserRequest{
		Username: "ha_refresh_" + marker, Password: "ha-refresh-password-123", Metadata: map[string]string{},
	})
	if err != nil {
		t.Fatalf("create refresh subject: %v", err)
	}
	registered, err := cluster.apps[0].clientService.Create(ctx, models.CreateClientRequest{
		Name: "HA refresh client", RedirectURIs: []string{"https://client.invalid/refresh/" + marker},
		Grants: []string{models.GrantAuthorizationCode, models.GrantRefreshToken},
		Scopes: []string{"profile", "offline_access"}, IsPublic: true,
	})
	if err != nil {
		t.Fatalf("create refresh OAuth client: %v", err)
	}

	oldRefresh := "ha-refresh-old-" + marker
	refreshData := &session.TokenData{
		ClientID: registered.ID, UserID: current.ID.String(), Scopes: []string{"offline_access", "profile"},
		AuthVersion: current.AuthVersion, AuthorizationIssuedAt: time.Now().UTC().UnixMicro(),
	}
	if err := cluster.apps[0].sessionStore.SaveRefreshToken(ctx, oldRefresh, refreshData, time.Hour); err != nil {
		t.Fatalf("store initial refresh token: %v", err)
	}
	oldRefreshKey := "nyauth:refresh:" + haDigest(oldRefresh)
	oldUsedKey := "nyauth:refresh-used:" + haDigest(oldRefresh)
	familyKey := "nyauth:refresh-family:" + refreshData.FamilyKey
	revokedKey := "nyauth:refresh-revoked:" + refreshData.FamilyKey
	userFamiliesKey := "nyauth:user-refresh-families:" + haDigest(current.ID.String())
	for _, key := range []string{oldRefreshKey, oldUsedKey, familyKey, revokedKey, userFamiliesKey} {
		cluster.trackRedisKey(key)
	}

	start := make(chan struct{})
	results := make(chan haTokenHTTPResult, 2)
	var workers sync.WaitGroup
	for instance := range 2 {
		workers.Add(1)
		go func(instance int) {
			defer workers.Done()
			<-start
			results <- cluster.refreshGrant(instance, registered.ID, oldRefresh)
		}(instance)
	}
	close(start)
	workers.Wait()
	close(results)

	successes := 0
	invalidGrants := 0
	var rotated auth.TokenPair
	for result := range results {
		if result.err != nil {
			t.Fatalf("rotate refresh token: %v", result.err)
		}
		switch result.status {
		case http.StatusOK:
			successes++
			if err := json.Unmarshal(result.body, &rotated); err != nil {
				t.Fatalf("decode successful refresh response: %v; body=%s", err, result.body)
			}
		case http.StatusBadRequest:
			if !isHAInvalidGrant(result.body) {
				t.Fatalf("unexpected failed refresh response: status=%d body=%s", result.status, result.body)
			}
			invalidGrants++
		default:
			t.Fatalf("unexpected refresh response: status=%d body=%s", result.status, result.body)
		}
	}
	if successes != 1 || invalidGrants != 1 || rotated.RefreshToken == "" || rotated.AccessToken == "" {
		t.Fatalf("refresh outcomes: success=%d invalid_grant=%d refresh_present=%v access_present=%v", successes, invalidGrants, rotated.RefreshToken != "", rotated.AccessToken != "")
	}

	newRefreshKey := "nyauth:refresh:" + haDigest(rotated.RefreshToken)
	cluster.trackRedisKey(newRefreshKey)
	claims := &auth.Claims{}
	if _, _, err := jwt.NewParser().ParseUnverified(rotated.AccessToken, claims); err != nil || claims.ID == "" {
		t.Fatalf("parse rotated access token metadata: jti=%q err=%v", claims.ID, err)
	}
	newAccessKey := "nyauth:token:" + haDigest(claims.ID)
	cluster.trackRedisKey(newAccessKey)

	replay := cluster.refreshGrant(0, registered.ID, oldRefresh)
	if replay.err != nil || replay.status != http.StatusBadRequest || !isHAInvalidGrant(replay.body) {
		t.Fatalf("reused old refresh response: status=%d body=%s err=%v", replay.status, replay.body, replay.err)
	}
	if exists, err := cluster.redisClients[1].Exists(ctx, revokedKey).Result(); err != nil || exists != 1 {
		t.Fatalf("refresh family revocation marker: exists=%d err=%v", exists, err)
	}
	for name, key := range map[string]string{"new refresh": newRefreshKey, "new access": newAccessKey} {
		if exists, err := cluster.redisClients[1].Exists(ctx, key).Result(); err != nil || exists != 0 {
			t.Fatalf("%s survived reused-family revocation: exists=%d err=%v", name, exists, err)
		}
	}

	newTokenAttempt := cluster.refreshGrant(1, registered.ID, rotated.RefreshToken)
	if newTokenAttempt.err != nil || newTokenAttempt.status != http.StatusBadRequest || !isHAInvalidGrant(newTokenAttempt.body) {
		t.Fatalf("revoked replacement refresh response: status=%d body=%s err=%v", newTokenAttempt.status, newTokenAttempt.body, newTokenAttempt.err)
	}
}

func TestHAAvatarUploadReadAndDelete(t *testing.T) {
	cluster := newHAHTTPTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), haIntegrationTimeout)
	defer cancel()
	username := "avatar_http_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	created, err := cluster.apps[0].userService.Create(ctx, models.CreateUserRequest{
		Username: username, Password: "Avatar-http-test-123!", DisplayName: "Avatar HTTP",
	})
	if err != nil {
		t.Fatalf("create avatar HTTP user: %v", err)
	}
	for _, action := range []string{"upload", "delete"} {
		cluster.trackRedisKey("nyauth:avatar-limit:subject:" + action + ":" + limitDigest("198.51.100.81\x00"+created.ID.String()))
		cluster.trackRedisKey("nyauth:avatar-limit:ip:" + action + ":" + limitDigest("198.51.100.81"))
	}
	login := cluster.login(t, 0, created.Username, "Avatar-http-test-123!", "198.51.100.81")

	var uploadBody bytes.Buffer
	writer := multipart.NewWriter(&uploadBody)
	part, err := writer.CreateFormFile("avatar", "avatar.png")
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewRGBA(image.Rect(0, 0, 96, 96))
	for y := 0; y < 96; y++ {
		for x := 0; x < 96; x++ {
			img.Set(x, y, color.RGBA{R: 0x7a, G: 0x5a, B: 0xff, A: 0xff})
		}
	}
	if err := png.Encode(part, img); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, cluster.httpServers[0].URL+"/api/me/avatar", &uploadBody)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(login.cookie)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("X-CSRF-Token", login.session.CSRFToken)
	request.Header.Set("X-Forwarded-For", "198.51.100.81")
	response, err := cluster.httpServers[0].Client().Do(request)
	if err != nil {
		t.Fatalf("upload avatar: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		body := readHAResponse(t, response)
		t.Fatalf("upload avatar status=%d body=%s", response.StatusCode, body)
	}
	var updated models.User
	if err := json.NewDecoder(response.Body).Decode(&updated); err != nil {
		_ = response.Body.Close()
		t.Fatalf("decode upload response: %v", err)
	}
	_ = response.Body.Close()
	if updated.AvatarURL == nil || !strings.HasSuffix(*updated.AvatarURL, "/256.webp") {
		t.Fatalf("avatar URL = %v", updated.AvatarURL)
	}

	mediaResponse := cluster.request(t, 1, http.MethodGet, *updated.AvatarURL, nil, nil, "", "198.51.100.82")
	if mediaResponse.StatusCode != http.StatusOK || mediaResponse.Header.Get("Content-Type") != "image/webp" || mediaResponse.Header.Get("X-Content-Type-Options") != "nosniff" {
		body := readHAResponse(t, mediaResponse)
		t.Fatalf("media response status=%d headers=%v body=%s", mediaResponse.StatusCode, mediaResponse.Header, body)
	}
	_ = readHAResponse(t, mediaResponse)

	deleteResponse := cluster.request(t, 1, http.MethodDelete, "/api/me/avatar", nil, login.cookie, login.session.CSRFToken, "198.51.100.81")
	if deleteResponse.StatusCode != http.StatusOK {
		body := readHAResponse(t, deleteResponse)
		t.Fatalf("delete avatar status=%d body=%s", deleteResponse.StatusCode, body)
	}
	var removed models.User
	if err := json.NewDecoder(deleteResponse.Body).Decode(&removed); err != nil {
		_ = deleteResponse.Body.Close()
		t.Fatalf("decode delete avatar response: %v", err)
	}
	_ = deleteResponse.Body.Close()
	if removed.AvatarURL != nil {
		t.Fatalf("removed avatar URL = %v", removed.AvatarURL)
	}
	missingResponse := cluster.request(t, 0, http.MethodGet, *updated.AvatarURL, nil, nil, "", "198.51.100.82")
	if missingResponse.StatusCode != http.StatusNotFound {
		body := readHAResponse(t, missingResponse)
		t.Fatalf("deleted media status=%d body=%s", missingResponse.StatusCode, body)
	}
	_ = missingResponse.Body.Close()
}

func newHAHTTPTestCluster(t *testing.T) *haHTTPTestCluster {
	t.Helper()
	baseDSN := strings.TrimSpace(os.Getenv("NYAUTH_TEST_DATABASE_DSN"))
	redisAddr := strings.TrimSpace(os.Getenv("NYAUTH_TEST_REDIS_ADDR"))
	if baseDSN == "" || redisAddr == "" {
		t.Skip("NYAUTH_TEST_DATABASE_DSN and NYAUTH_TEST_REDIS_ADDR are required for HA HTTP integration tests")
	}

	databaseNumber := 0
	if configured := strings.TrimSpace(os.Getenv("NYAUTH_TEST_REDIS_DB")); configured != "" {
		parsed, err := strconv.Atoi(configured)
		if err != nil || parsed < 0 {
			t.Fatalf("invalid NYAUTH_TEST_REDIS_DB %q", configured)
		}
		databaseNumber = parsed
	}

	ctx, cancel := context.WithTimeout(context.Background(), haIntegrationTimeout)
	defer cancel()
	basePool, err := pgxpool.New(ctx, baseDSN)
	if err != nil {
		t.Fatalf("connect integration PostgreSQL: %v", err)
	}
	if err := basePool.Ping(ctx); err != nil {
		basePool.Close()
		t.Fatalf("ping integration PostgreSQL: %v", err)
	}
	schemaName := "nyauth_http_ha_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schemaName}.Sanitize()
	if _, err := basePool.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		basePool.Close()
		t.Fatalf("create isolated HA schema: %v", err)
	}

	cluster := &haHTTPTestCluster{redisKeys: make(map[string]struct{}), sessionMembers: make(map[string]struct{})}
	var pools []*pgxpool.Pool
	var testServers []*httptest.Server
	var redisClients []*redis.Client
	var telemetryRuntime *telemetry.Runtime
	t.Cleanup(func() {
		for _, testServer := range testServers {
			testServer.Close()
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), haIntegrationTimeout)
		defer cleanupCancel()
		if telemetryRuntime != nil {
			if err := telemetryRuntime.Shutdown(cleanupCtx); err != nil {
				t.Errorf("shutdown HA test telemetry: %v", err)
			}
		}
		if len(redisClients) > 0 {
			keys := make([]string, 0, len(cluster.redisKeys))
			for key := range cluster.redisKeys {
				keys = append(keys, key)
			}
			if len(keys) > 0 {
				if err := redisClients[0].Del(cleanupCtx, keys...).Err(); err != nil {
					t.Errorf("remove isolated HA Redis keys: %v", err)
				}
			}
			members := make([]interface{}, 0, len(cluster.sessionMembers))
			for member := range cluster.sessionMembers {
				members = append(members, member)
			}
			if len(members) > 0 {
				if err := redisClients[0].ZRem(cleanupCtx, "nyauth:sessions", members...).Err(); err != nil {
					t.Errorf("remove isolated HA session index entries: %v", err)
				}
			}
		}
		for _, client := range redisClients {
			_ = client.Close()
		}
		for _, pool := range pools {
			pool.Close()
		}
		if _, err := basePool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated HA schema %s: %v", schemaName, err)
		}
		basePool.Close()
	})

	scopedDSN := haDSNWithSearchPath(t, baseDSN, schemaName)
	if err := database.RunMigrations(scopedDSN); err != nil {
		t.Fatalf("migrate isolated HA schema: %v", err)
	}
	for index := range 2 {
		poolConfig, err := pgxpool.ParseConfig(baseDSN)
		if err != nil {
			t.Fatalf("parse PostgreSQL DSN for instance %d: %v", index, err)
		}
		if poolConfig.ConnConfig.RuntimeParams == nil {
			poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
		}
		poolConfig.ConnConfig.RuntimeParams["search_path"] = schemaName
		pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
		if err != nil {
			t.Fatalf("connect PostgreSQL instance %d: %v", index, err)
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			t.Fatalf("ping PostgreSQL instance %d: %v", index, err)
		}
		pools = append(pools, pool)

		redisClient := redis.NewClient(&redis.Options{
			Addr: redisAddr, Username: os.Getenv("NYAUTH_TEST_REDIS_USERNAME"),
			Password: os.Getenv("NYAUTH_TEST_REDIS_PASSWORD"), DB: databaseNumber,
		})
		if err := redisClient.Ping(ctx).Err(); err != nil {
			_ = redisClient.Close()
			t.Fatalf("ping Redis instance %d: %v", index, err)
		}
		redisClients = append(redisClients, redisClient)
		cluster.redisClients[index] = redisClient
	}

	telemetryRuntime, err = telemetry.New(ctx, telemetry.Options{})
	if err != nil {
		t.Fatalf("create HA integration telemetry: %v", err)
	}
	cfg := haTestConfig(t)
	for index := range 2 {
		app, err := New(cfg, pools[index], redisClients[index], embed.FS{}, telemetryRuntime)
		if err != nil {
			t.Fatalf("create HTTP server instance %d: %v", index, err)
		}
		cluster.apps[index] = app
	}
	if err := cluster.apps[0].jwkManager.EnsureActiveKey(ctx); err != nil {
		t.Fatalf("initialize shared signing key: %v", err)
	}
	for index := range 2 {
		testServer := httptest.NewServer(cluster.apps[index].router)
		testServers = append(testServers, testServer)
		cluster.httpServers[index] = testServer
	}
	return cluster
}

func haTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Environment: "test",
		Server: config.ServerConfig{
			SecureCookie: false, TrustedProxyCIDRs: []string{"127.0.0.0/8"},
			ReadinessTimeout: 2 * time.Second, ShutdownTimeout: 2 * time.Second,
		},
		Auth: config.AuthConfig{
			Issuer: "http://nyauth-ha.invalid", MasterKey: []byte("0123456789abcdef0123456789abcdef"),
			Argon2Concurrency: 2, AccessTokenTTL: 5 * time.Minute, RefreshTokenTTL: time.Hour,
			AuthorizationCodeTTL: time.Minute,
			JWK:                  config.JWKConfig{Algorithm: "RS256", KeySize: 2048, RotationInterval: 24 * time.Hour},
		},
		Media: config.MediaConfig{Backend: "local", Local: config.LocalMediaConfig{Directory: t.TempDir()}},
	}
}

func (c *haHTTPTestCluster) login(t *testing.T, instance int, username, password, ip string) haLogin {
	t.Helper()
	body, err := json.Marshal(models.LoginRequest{Username: username, Password: password})
	if err != nil {
		t.Fatalf("encode login request: %v", err)
	}
	response := c.request(t, instance, http.MethodPost, "/api/login", bytes.NewReader(body), nil, "", ip)
	if response.StatusCode != http.StatusOK {
		responseBody := readHAResponse(t, response)
		t.Fatalf("login %q through instance %d: status=%d body=%s", username, instance, response.StatusCode, responseBody)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range response.Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly {
		_ = readHAResponse(t, response)
		t.Fatalf("login response is missing an HttpOnly session cookie: %#v", sessionCookie)
	}
	sessionKey := "nyauth:session:" + haDigest(sessionCookie.Value)
	c.trackRedisKey(sessionKey)
	c.sessionMembers[sessionKey] = struct{}{}
	var payload models.SessionResponse
	decodeHAResponse(t, response, &payload)
	if payload.User == nil || payload.CSRFToken == "" {
		t.Fatalf("login response is missing hardened session state: cookie=%#v payload=%#v", sessionCookie, payload)
	}
	c.trackRedisKey("nyauth:user-sessions:" + haDigest(payload.User.ID.String()))
	c.trackRedisKey("nyauth:login-limit:identity:" + limitDigest(ip+"\x00"+strings.ToLower(username)))
	c.trackRedisKey("nyauth:login-limit:ip:" + limitDigest(ip))
	return haLogin{cookie: sessionCookie, session: payload}
}

func (c *haHTTPTestCluster) request(t *testing.T, instance int, method, path string, body io.Reader, cookie *http.Cookie, csrf, ip string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, c.httpServers[instance].URL+path, body)
	if err != nil {
		t.Fatalf("create %s %s request: %v", method, path, err)
	}
	if body != nil {
		if path == "/token" || path == "/revoke" {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			request.Header.Set("Content-Type", "application/json")
		}
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	if ip != "" {
		request.Header.Set("X-Forwarded-For", ip)
	}
	response, err := c.httpServers[instance].Client().Do(request)
	if err != nil {
		t.Fatalf("perform %s %s through instance %d: %v", method, path, instance, err)
	}
	return response
}

func (c *haHTTPTestCluster) passkeyRequest(
	t *testing.T,
	instance int,
	path string,
	body []byte,
	ceremonyID, ip string,
) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, c.httpServers[instance].URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create Passkey request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(webAuthnCeremonyHeader, ceremonyID)
	if ip != "" {
		request.Header.Set("X-Forwarded-For", ip)
	}
	response, err := c.httpServers[instance].Client().Do(request)
	if err != nil {
		t.Fatalf("execute Passkey request through instance %d: %v", instance, err)
	}
	return response
}

func insertHAPasskeyFixture(
	t *testing.T,
	ctx context.Context,
	db *pgxpool.Pool,
	userID uuid.UUID,
) haPasskeyFixture {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate HA Passkey key: %v", err)
	}
	credentialID := make([]byte, 32)
	userHandle := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("generate HA Passkey credential ID: %v", err)
	}
	if _, err := rand.Read(userHandle); err != nil {
		t.Fatalf("generate HA Passkey user handle: %v", err)
	}
	publicKey, err := cbor.Marshal(map[int]any{
		1: 2, 3: -7, -1: 1,
		-2: privateKey.PublicKey.X.FillBytes(make([]byte, 32)),
		-3: privateKey.PublicKey.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("encode HA Passkey public key: %v", err)
	}
	credential := gowebauthn.Credential{
		ID: credentialID, PublicKey: publicKey, AttestationFormat: "none",
		Flags: gowebauthn.CredentialFlags{UserPresent: true, UserVerified: true},
		Authenticator: gowebauthn.Authenticator{
			AAGUID: make([]byte, 16), Attachment: protocol.Platform,
		},
	}
	encoded, err := credential.MarshalMsg(nil)
	if err != nil {
		t.Fatalf("encode HA Passkey credential: %v", err)
	}
	rowID := uuid.New()
	ciphertext, err := nyacrypto.EncryptEnvelope(
		[]byte("0123456789abcdef0123456789abcdef"), "primary", "mfa.passkey.credential", encoded,
		haPasskeyAAD("nyauth-ha.invalid", rowID, userID, credentialID),
	)
	if err != nil {
		t.Fatalf("encrypt HA Passkey credential: %v", err)
	}
	if _, err := db.Exec(ctx, `
		WITH inserted_handle AS (
			INSERT INTO user_passkey_handles (rp_id,user_id,user_handle)
			VALUES ($1,$2,$3)
			RETURNING rp_id,user_id
		)
		INSERT INTO user_passkey_credentials (
			id,rp_id,user_id,credential_id,credential_ciphertext,name,aaguid,attachment
		)
		SELECT $4,rp_id,user_id,$5,$6,'HA Passkey',$7,'platform'
		FROM inserted_handle
	`, "nyauth-ha.invalid", userID, userHandle, rowID, credentialID, ciphertext, make([]byte, 16)); err != nil {
		t.Fatalf("insert HA Passkey fixture: %v", err)
	}
	return haPasskeyFixture{credentialID: credentialID, userHandle: userHandle, privateKey: privateKey}
}

func haPasskeyAssertionPayload(
	t *testing.T,
	options protocol.PublicKeyCredentialRequestOptions,
	fixture haPasskeyFixture,
	signCount uint32,
) []byte {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte("nyauth-ha.invalid"))
	authenticatorData := make([]byte, 37)
	copy(authenticatorData, rpIDHash[:])
	authenticatorData[32] = 0x01 | 0x04
	binary.BigEndian.PutUint32(authenticatorData[33:], signCount)
	clientDataJSON, err := json.Marshal(map[string]any{
		"type": "webauthn.get", "challenge": options.Challenge.String(),
		"origin": "http://nyauth-ha.invalid", "crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("encode HA assertion client data: %v", err)
	}
	clientDataHash := sha256.Sum256(clientDataJSON)
	signedData := make([]byte, 0, len(authenticatorData)+len(clientDataHash))
	signedData = append(signedData, authenticatorData...)
	signedData = append(signedData, clientDataHash[:]...)
	signedHash := sha256.Sum256(signedData)
	signature, err := ecdsa.SignASN1(rand.Reader, fixture.privateKey, signedHash[:])
	if err != nil {
		t.Fatalf("sign HA Passkey assertion: %v", err)
	}
	encodedCredentialID := base64.RawURLEncoding.EncodeToString(fixture.credentialID)
	payload, err := json.Marshal(map[string]any{
		"id": encodedCredentialID, "rawId": encodedCredentialID, "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authenticatorData),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
			"userHandle":        base64.RawURLEncoding.EncodeToString(fixture.userHandle),
		},
	})
	if err != nil {
		t.Fatalf("encode HA Passkey assertion: %v", err)
	}
	return payload
}

func haPasskeyAAD(rpID string, rowID, userID uuid.UUID, credentialID []byte) []byte {
	value := make([]byte, 0, len(rpID)+1+16+16+1+len(credentialID))
	value = append(value, rpID...)
	value = append(value, 0)
	value = append(value, rowID[:]...)
	value = append(value, userID[:]...)
	value = append(value, 0)
	return append(value, credentialID...)
}

func (c *haHTTPTestCluster) trackRedisKey(key string) {
	c.redisKeys[key] = struct{}{}
}

func (c *haHTTPTestCluster) auditPayload(t *testing.T, event, aggregateID, result string) (map[string]any, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), haIntegrationTimeout)
	defer cancel()
	var encoded []byte
	if err := c.apps[0].db.QueryRow(ctx, `
		SELECT payload FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='client' AND aggregate_id=$2 AND payload->>'result'=$3
		ORDER BY created_at DESC LIMIT 1
	`, event, aggregateID, result).Scan(&encoded); err != nil {
		t.Fatalf("load %s %s audit outbox event: %v", event, result, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("decode %s %s audit outbox payload: %v", event, result, err)
	}
	return payload, encoded
}

func (c *haHTTPTestCluster) refreshGrant(instance int, clientID, refreshToken string) haTokenHTTPResult {
	form := url.Values{
		"grant_type":    {models.GrantRefreshToken},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	}
	request, err := http.NewRequest(http.MethodPost, c.httpServers[instance].URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return haTokenHTTPResult{err: err}
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.httpServers[instance].Client().Do(request)
	if err != nil {
		return haTokenHTTPResult{err: err}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	return haTokenHTTPResult{status: response.StatusCode, body: body, err: err}
}

func isHAInvalidGrant(body []byte) bool {
	var payload struct {
		Error string `json:"error"`
	}
	return json.Unmarshal(body, &payload) == nil && payload.Error == "invalid_grant"
}

func decodeHAResponse(t *testing.T, response *http.Response, target any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target); err != nil {
		t.Fatalf("decode status %d response: %v", response.StatusCode, err)
	}
}

func readHAResponse(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatalf("read status %d response: %v", response.StatusCode, err)
	}
	return string(body)
}

func responseClearsCookie(response *http.Response, name string) bool {
	for _, cookie := range response.Cookies() {
		if cookie.Name == name && cookie.MaxAge < 0 {
			return true
		}
	}
	return false
}

func haDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func haDSNWithSearchPath(t *testing.T, dsn, schemaName string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err == nil && (parsed.Scheme == "postgres" || parsed.Scheme == "postgresql") {
		query := parsed.Query()
		query.Set("search_path", schemaName)
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	return fmt.Sprintf("%s search_path=%s", strings.TrimSpace(dsn), schemaName)
}
