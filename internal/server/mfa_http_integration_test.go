package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	nyacrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/mfa"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestPasswordLoginRequiresMFAAndCreatesSessionOnlyAfterVerification(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	const password = "correct horse battery staple"
	passwordHash, err := nyacrypto.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	admin := &models.User{
		ID: uuid.New(), Username: "mfa-http-admin", PasswordHash: &passwordHash,
		Status: models.UserStatusActive, Role: "admin", AuthVersion: 1, SessionVersion: 1,
		Metadata: map[string]string{},
	}
	if err := user.NewStore(testApp.pool).Create(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	enrolledFactor := enrollHTTPTestTOTP(t, testApp, admin, time.Now().UTC().Add(-2*time.Minute))
	secret := enrolledFactor.Secret

	login := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/login", `{
		"username":"mfa-http-admin",
		"password":"correct horse battery staple",
		"return_to":"/authorize?client_id=test"
	}`, "", "")
	if login.Code != http.StatusAccepted {
		t.Fatalf("login status=%d body=%s", login.Code, login.Body.String())
	}
	var challenge models.MFARequiredResponse
	if err := json.Unmarshal(login.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.Status != "mfa_required" || challenge.CSRFToken == "" || len(challenge.Methods) != 2 ||
		!challenge.TrustedDeviceAvailable || challenge.TrustedDeviceTTLSeconds != int64(30*24*time.Hour/time.Second) {
		t.Fatalf("challenge=%#v", challenge)
	}
	pendingCookie := responseCookie(t, login, mfaPendingCookieName)
	if count, err := testApp.app.sessionStore.CountActiveSessions(context.Background()); err != nil || count != 0 {
		t.Fatalf("active sessions before MFA=%d err=%v", count, err)
	}

	pendingCookieHeader := pendingCookie.Name + "=" + pendingCookie.Value
	unauthenticatedSession := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/session", "", pendingCookieHeader, "")
	if unauthenticatedSession.Code != http.StatusUnauthorized {
		t.Fatalf("pending challenge accessed session endpoint: %d", unauthenticatedSession.Code)
	}
	restored := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/login/mfa", "", pendingCookieHeader, "")
	if restored.Code != http.StatusOK {
		t.Fatalf("restore status=%d body=%s", restored.Code, restored.Body.String())
	}

	validCode := serverIntegrationTOTPCode(secret, time.Now().UTC().Unix()/30)
	invalidCode := "0" + validCode[1:]
	if invalidCode == validCode {
		invalidCode = "1" + validCode[1:]
	}
	invalid := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/login/mfa",
		fmt.Sprintf(`{"method":"totp","code":%q}`, invalidCode), pendingCookieHeader, challenge.CSRFToken)
	if invalid.Code != http.StatusUnauthorized {
		t.Fatalf("invalid MFA status=%d body=%s", invalid.Code, invalid.Body.String())
	}

	verified := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/login/mfa",
		fmt.Sprintf(`{"method":"totp","code":%q,"trust_device":true}`, validCode), pendingCookieHeader, challenge.CSRFToken)
	if verified.Code != http.StatusOK {
		t.Fatalf("verified MFA status=%d body=%s", verified.Code, verified.Body.String())
	}
	sessionCookie := responseCookie(t, verified, sessionCookieName)
	trustedDeviceCookie := responseCookie(t, verified, trustedDeviceCookieName)
	var sessionResponse models.SessionResponse
	if err := json.Unmarshal(verified.Body.Bytes(), &sessionResponse); err != nil {
		t.Fatal(err)
	}
	if sessionResponse.User == nil || sessionResponse.User.ID != admin.ID || sessionResponse.CSRFToken == "" {
		t.Fatalf("session response=%#v", sessionResponse)
	}
	if count, err := testApp.app.sessionStore.CountActiveSessions(context.Background()); err != nil || count != 1 {
		t.Fatalf("active sessions after MFA=%d err=%v", count, err)
	}
	trustedLogin := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/login", `{
		"username":"mfa-http-admin",
		"password":"correct horse battery staple",
		"return_to":"/dashboard"
	}`, trustedDeviceCookie.Name+"="+trustedDeviceCookie.Value, "")
	if trustedLogin.Code != http.StatusOK {
		t.Fatalf("trusted device login status=%d body=%s", trustedLogin.Code, trustedLogin.Body.String())
	}
	sessionCookieHeader := sessionCookie.Name + "=" + sessionCookie.Value
	currentSession := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/session", "", sessionCookieHeader, "")
	if currentSession.Code != http.StatusOK {
		t.Fatalf("session status=%d body=%s", currentSession.Code, currentSession.Body.String())
	}
	storedSession, err := testApp.app.sessionStore.GetSession(context.Background(), sessionCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	staleAuthenticatedAt := time.Now().UTC().Add(-11 * time.Minute)
	storedSession.AuthenticatedAt = staleAuthenticatedAt
	if err := testApp.app.sessionStore.SaveSession(context.Background(), sessionCookie.Value, storedSession, sessionTTL); err != nil {
		t.Fatal(err)
	}
	passwordReauth := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/me/reauth/password",
		`{"password":"correct horse battery staple"}`, sessionCookieHeader, sessionResponse.CSRFToken)
	if passwordReauth.Code != http.StatusAccepted {
		t.Fatalf("password reauth status=%d body=%s", passwordReauth.Code, passwordReauth.Body.String())
	}
	var reauthChallenge models.MFARequiredResponse
	if err := json.Unmarshal(passwordReauth.Body.Bytes(), &reauthChallenge); err != nil {
		t.Fatal(err)
	}
	if reauthChallenge.Purpose != mfaPurposeReauthentication || reauthChallenge.TrustedDeviceAvailable || reauthChallenge.TrustedDeviceTTLSeconds != 0 {
		t.Fatalf("reauth challenge=%#v", reauthChallenge)
	}
	stillStale, err := testApp.app.sessionStore.GetSession(context.Background(), sessionCookie.Value)
	if err != nil || !stillStale.AuthenticatedAt.Equal(staleAuthenticatedAt) {
		t.Fatalf("primary-only reauth refreshed session: %#v err=%v", stillStale, err)
	}
	reauthPendingCookie := responseCookie(t, passwordReauth, mfaPendingCookieName)
	reauthCookieHeader := sessionCookieHeader + "; " + reauthPendingCookie.Name + "=" + reauthPendingCookie.Value
	completedReauth := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/login/mfa",
		fmt.Sprintf(`{"method":"recovery_code","code":%q}`, enrolledFactor.RecoveryCodes[0]),
		reauthCookieHeader, reauthChallenge.CSRFToken)
	if completedReauth.Code != http.StatusOK {
		t.Fatalf("completed reauth=%d body=%s", completedReauth.Code, completedReauth.Body.String())
	}
	if err := json.Unmarshal(completedReauth.Body.Bytes(), &sessionResponse); err != nil {
		t.Fatal(err)
	}
	if sessionResponse.AuthenticatedAt == nil || time.Since(*sessionResponse.AuthenticatedAt) > time.Minute {
		t.Fatalf("reauthenticated_at=%v", sessionResponse.AuthenticatedAt)
	}
	mfaStatus := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/me/mfa", "", sessionCookieHeader, "")
	if mfaStatus.Code != http.StatusOK {
		t.Fatalf("MFA status=%d body=%s", mfaStatus.Code, mfaStatus.Body.String())
	}
	requireAdminMFA := mfaHTTPRequest(testApp.app, http.MethodPut, "/api/admin/settings/security",
		`{"totp_enabled":true,"require_mfa_for_admins":true}`, sessionCookieHeader, sessionResponse.CSRFToken)
	if requireAdminMFA.Code != http.StatusOK {
		t.Fatalf("require administrator MFA=%d body=%s", requireAdminMFA.Code, requireAdminMFA.Body.String())
	}
	disableRequiredMFA := mfaHTTPRequest(testApp.app, http.MethodDelete, "/api/me/mfa/totp", "", sessionCookieHeader, sessionResponse.CSRFToken)
	if disableRequiredMFA.Code != http.StatusConflict {
		t.Fatalf("disable required MFA=%d body=%s", disableRequiredMFA.Code, disableRequiredMFA.Body.String())
	}
	consumedRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	consumedRequest.AddCookie(pendingCookie)
	if _, err := testApp.app.sessionMiddleware.GetMFAPending(consumedRequest); err == nil {
		t.Fatal("consumed MFA pending state remained available")
	}
	var failedChallenges int
	if err := testApp.pool.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1 AND aggregate_id=$2
	`, models.AuditMFAChallengeFailed, admin.ID.String()).Scan(&failedChallenges); err != nil {
		t.Fatal(err)
	}
	if failedChallenges != 1 {
		t.Fatalf("failed challenge audit count=%d", failedChallenges)
	}
}

func TestTOTPSecurityCenterHTTPFlow(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	const password = "security center password"
	passwordHash, err := nyacrypto.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	current := &models.User{
		ID: uuid.New(), Username: "totp-security-user", PasswordHash: &passwordHash,
		Status: models.UserStatusActive, Role: "user", AuthVersion: 1, SessionVersion: 1,
		Metadata: map[string]string{},
	}
	if err := user.NewStore(testApp.pool).Create(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	login := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/login", `{
		"username":"totp-security-user","password":"security center password"
	}`, "", "")
	if login.Code != http.StatusOK {
		t.Fatalf("initial login=%d body=%s", login.Code, login.Body.String())
	}
	var initialSession models.SessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &initialSession); err != nil {
		t.Fatal(err)
	}
	initialCookie := responseCookie(t, login, sessionCookieName)
	initialCookieHeader := initialCookie.Name + "=" + initialCookie.Value

	begin := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/me/mfa/totp/enroll", "{}", initialCookieHeader, initialSession.CSRFToken)
	if begin.Code != http.StatusOK {
		t.Fatalf("begin enrollment=%d body=%s", begin.Code, begin.Body.String())
	}
	var enrollment mfa.Enrollment
	if err := json.Unmarshal(begin.Body.Bytes(), &enrollment); err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	code := serverIntegrationTOTPCode(secret, time.Now().UTC().Unix()/30)
	confirm := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/me/mfa/totp/enroll/confirm",
		fmt.Sprintf(`{"code":%q}`, code), initialCookieHeader, initialSession.CSRFToken)
	if confirm.Code != http.StatusOK {
		t.Fatalf("confirm enrollment=%d body=%s", confirm.Code, confirm.Body.String())
	}
	var confirmed totpConfirmationResponse
	if err := json.Unmarshal(confirm.Body.Bytes(), &confirmed); err != nil {
		t.Fatal(err)
	}
	if confirmed.SessionResponse == nil || confirmed.CSRFToken == "" || len(confirmed.RecoveryCodes) != 10 {
		t.Fatalf("confirmed response=%#v", confirmed)
	}
	confirmedCookie := responseCookie(t, confirm, sessionCookieName)
	confirmedCookieHeader := confirmedCookie.Name + "=" + confirmedCookie.Value
	status := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/me/mfa", "", confirmedCookieHeader, "")
	if status.Code != http.StatusOK ||
		!bytes.Contains(status.Body.Bytes(), []byte(`"totp_enrolled":true`)) ||
		!bytes.Contains(status.Body.Bytes(), []byte(`"required_for_current_user":false`)) {
		t.Fatalf("enrolled status=%d body=%s", status.Code, status.Body.String())
	}
	regenerated := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/me/mfa/recovery-codes", "{}", confirmedCookieHeader, confirmed.CSRFToken)
	if regenerated.Code != http.StatusOK {
		t.Fatalf("regenerate recovery codes=%d body=%s", regenerated.Code, regenerated.Body.String())
	}
	var regeneratedCodes recoveryCodesResponse
	if err := json.Unmarshal(regenerated.Body.Bytes(), &regeneratedCodes); err != nil || len(regeneratedCodes.RecoveryCodes) != 10 {
		t.Fatalf("regenerated response=%#v err=%v", regeneratedCodes, err)
	}
	disabled := mfaHTTPRequest(testApp.app, http.MethodDelete, "/api/me/mfa/totp", "", confirmedCookieHeader, confirmed.CSRFToken)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable TOTP=%d body=%s", disabled.Code, disabled.Body.String())
	}
	var disabledSession models.SessionResponse
	if err := json.Unmarshal(disabled.Body.Bytes(), &disabledSession); err != nil {
		t.Fatal(err)
	}
	disabledCookie := responseCookie(t, disabled, sessionCookieName)
	disabledCookieHeader := disabledCookie.Name + "=" + disabledCookie.Value
	status = mfaHTTPRequest(testApp.app, http.MethodGet, "/api/me/mfa", "", disabledCookieHeader, "")
	if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"totp_enrolled":false`)) {
		t.Fatalf("disabled status=%d body=%s", status.Code, status.Body.String())
	}
	if stale := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/session", "", initialCookieHeader, ""); stale.Code != http.StatusUnauthorized {
		t.Fatalf("pre-enrollment session remained valid: %d", stale.Code)
	}
}

func TestProviderLoginUsesTheSameMFAPendingFlow(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	current, enrolledFactor := createHTTPTestProviderMFAUser(t, testApp, "provider-mfa-user", "provider-mfa-external")
	secret := enrolledFactor.Secret

	callbackRequest := httptest.NewRequest(http.MethodGet, "/auth/github/callback", nil)
	callbackRequest.RemoteAddr = "192.0.2.30:43000"
	callbackRecorder := httptest.NewRecorder()
	testApp.app.finishExternalLogin(callbackRecorder, callbackRequest, "github", "/dashboard", &models.ExternalUser{
		ID: "provider-mfa-external", Username: "provider-user",
	})
	if callbackRecorder.Code != http.StatusFound {
		t.Fatalf("provider callback status=%d body=%s", callbackRecorder.Code, callbackRecorder.Body.String())
	}
	if location := callbackRecorder.Header().Get("Location"); location != "/login/mfa?return_to=%2Fdashboard" {
		t.Fatalf("provider MFA redirect=%q", location)
	}
	pendingCookie := responseCookie(t, callbackRecorder, mfaPendingCookieName)
	for _, cookie := range callbackRecorder.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			t.Fatal("provider primary authentication created a full session before MFA")
		}
	}
	if count, err := testApp.app.sessionStore.CountActiveSessions(context.Background()); err != nil || count != 0 {
		t.Fatalf("active sessions before provider MFA=%d err=%v", count, err)
	}
	pendingCookieHeader := pendingCookie.Name + "=" + pendingCookie.Value
	restored := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/login/mfa", "", pendingCookieHeader, "")
	if restored.Code != http.StatusOK {
		t.Fatalf("restore provider challenge=%d body=%s", restored.Code, restored.Body.String())
	}
	var challenge models.MFARequiredResponse
	if err := json.Unmarshal(restored.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	code := serverIntegrationTOTPCode(secret, time.Now().UTC().Unix()/30)
	verified := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/login/mfa",
		fmt.Sprintf(`{"method":"totp","code":%q}`, code), pendingCookieHeader, challenge.CSRFToken)
	if verified.Code != http.StatusOK {
		t.Fatalf("provider MFA verification=%d body=%s", verified.Code, verified.Body.String())
	}
	var primaryMethod, provider, secondFactor string
	if err := testApp.pool.QueryRow(context.Background(), `
		SELECT
			payload->'details'->>'authentication_method',
			payload->'details'->>'provider',
			payload->'details'->>'second_factor'
		FROM audit_event_outbox
		WHERE event=$1 AND aggregate_id=$2
		ORDER BY created_at DESC LIMIT 1
	`, models.AuditUserLogin, current.ID.String()).Scan(&primaryMethod, &provider, &secondFactor); err != nil {
		t.Fatal(err)
	}
	if primaryMethod != "provider" || provider != "github" || secondFactor != "totp" {
		t.Fatalf("login audit primary=%q provider=%q factor=%q", primaryMethod, provider, secondFactor)
	}
}

func TestProviderReauthenticationRequiresTheUsersSecondFactor(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	current, enrolledFactor := createHTTPTestProviderMFAUser(t, testApp, "provider-reauth-user", "provider-reauth-external")
	updated, err := testApp.app.userService.GetByID(context.Background(), current.ID)
	if err != nil {
		t.Fatal(err)
	}
	sessionRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	sessionRequest.RemoteAddr = "192.0.2.31:43001"
	sessionRecorder := httptest.NewRecorder()
	authenticated, err := testApp.app.sessionMiddleware.CreateSession(sessionRecorder, sessionRequest, updated)
	if err != nil {
		t.Fatal(err)
	}
	staleAuthenticatedAt := time.Now().UTC().Add(-11 * time.Minute)
	authenticated.Data.AuthenticatedAt = staleAuthenticatedAt
	if err := testApp.app.sessionStore.SaveSession(context.Background(), authenticated.ID, authenticated.Data, sessionTTL); err != nil {
		t.Fatal(err)
	}
	sessionCookie := responseCookie(t, sessionRecorder, sessionCookieName)

	callbackRequest := httptest.NewRequest(http.MethodGet, "/auth/github/callback", nil)
	callbackRequest.RemoteAddr = "192.0.2.31:43002"
	callbackRequest.AddCookie(sessionCookie)
	callbackRecorder := httptest.NewRecorder()
	testApp.app.finishExternalReauthentication(
		callbackRecorder, callbackRequest, "github", current.ID.String(),
		providerSessionDigest(authenticated.ID), "/profile",
		&models.ExternalUser{ID: "provider-reauth-external", Username: "provider-user"},
	)
	if callbackRecorder.Code != http.StatusFound {
		t.Fatalf("provider reauth status=%d body=%s", callbackRecorder.Code, callbackRecorder.Body.String())
	}
	if location := callbackRecorder.Header().Get("Location"); location != "/login/mfa?purpose=reauthentication&return_to=%2Fprofile" {
		t.Fatalf("provider reauth redirect=%q", location)
	}
	stillStale, err := testApp.app.sessionStore.GetSession(context.Background(), authenticated.ID)
	if err != nil || !stillStale.AuthenticatedAt.Equal(staleAuthenticatedAt) {
		t.Fatalf("provider primary reauth refreshed session: %#v err=%v", stillStale, err)
	}
	pendingCookie := responseCookie(t, callbackRecorder, mfaPendingCookieName)
	cookieHeader := sessionCookie.Name + "=" + sessionCookie.Value + "; " + pendingCookie.Name + "=" + pendingCookie.Value
	restored := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/login/mfa", "", cookieHeader, "")
	if restored.Code != http.StatusOK {
		t.Fatalf("restore provider reauth=%d body=%s", restored.Code, restored.Body.String())
	}
	var challenge models.MFARequiredResponse
	if err := json.Unmarshal(restored.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.Purpose != mfaPurposeReauthentication {
		t.Fatalf("provider reauth challenge=%#v", challenge)
	}
	completed := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/login/mfa",
		fmt.Sprintf(`{"method":"recovery_code","code":%q}`, enrolledFactor.RecoveryCodes[0]),
		cookieHeader, challenge.CSRFToken)
	if completed.Code != http.StatusOK {
		t.Fatalf("complete provider reauth=%d body=%s", completed.Code, completed.Body.String())
	}
	refreshed, err := testApp.app.sessionStore.GetSession(context.Background(), authenticated.ID)
	if err != nil || time.Since(refreshed.AuthenticatedAt) > time.Minute {
		t.Fatalf("provider reauth session=%#v err=%v", refreshed, err)
	}
}

func createHTTPTestProviderMFAUser(t *testing.T, testApp *registrationHTTPTestApp, username, externalID string) (*models.User, enrolledHTTPTestTOTP) {
	t.Helper()
	displayName := "Provider MFA User"
	current := &models.User{
		ID: uuid.New(), Username: username, DisplayName: &displayName,
		Status: models.UserStatusActive, Role: "user", AuthVersion: 1, SessionVersion: 1,
		Metadata: map[string]string{},
	}
	externalUsername := "provider-user"
	if err := testApp.app.identityStore.CreateUserAndIdentity(context.Background(), current, &models.Identity{
		ID: uuid.New(), UserID: current.ID, Provider: "github", ExternalID: externalID,
		ExternalUsername: &externalUsername, Metadata: map[string]string{},
	}); err != nil {
		t.Fatal(err)
	}
	enrolledFactor := enrollHTTPTestTOTP(t, testApp, current, time.Now().UTC().Add(-2*time.Minute))
	return current, enrolledFactor
}

type enrolledHTTPTestTOTP struct {
	Secret        []byte
	RecoveryCodes []string
}

func enrollHTTPTestTOTP(t *testing.T, testApp *registrationHTTPTestApp, current *models.User, enrollmentTime time.Time) enrolledHTTPTestTOTP {
	t.Helper()
	enrollment, err := testApp.app.mfaService.BeginEnrollment(
		context.Background(), current.ID, "Nyauth Test", current.Username, enrollmentTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentCode := serverIntegrationTOTPCode(secret, enrollmentTime.Unix()/30)
	recoveryCodes, err := testApp.app.mfaService.ConfirmEnrollment(
		context.Background(), current.ID, mfa.AuthenticationBinding{
			AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
		}, enrollmentCode,
		mfa.AuditContext{ActorID: current.ID, ActorName: current.Username}, enrollmentTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	return enrolledHTTPTestTOTP{Secret: secret, RecoveryCodes: recoveryCodes}
}

func mfaHTTPRequest(app *Server, method, path, body, cookie, csrfToken string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Origin", "https://auth.example.test")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	if csrfToken != "" {
		request.Header.Set("X-CSRF-Token", csrfToken)
	}
	request.RemoteAddr = "192.0.2.25:42000"
	recorder := httptest.NewRecorder()
	app.router.ServeHTTP(recorder, request)
	return recorder
}

func responseCookie(t *testing.T, recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name && cookie.Value != "" {
			return cookie
		}
	}
	t.Fatalf("response did not set cookie %q", name)
	return nil
}

func serverIntegrationTOTPCode(secret []byte, step int64) string {
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, uint64(step))
	digest := hmac.New(sha1.New, secret)
	_, _ = digest.Write(message)
	sum := digest.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1_000_000)
}
