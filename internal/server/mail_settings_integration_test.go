package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/mailruntime"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

type mailSettingsSMTPServer struct {
	listener net.Listener
	wg       sync.WaitGroup
	messages chan string
}

func newMailSettingsSMTPServer(t *testing.T, connections int) *mailSettingsSMTPServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mail settings SMTP server: %v", err)
	}
	server := &mailSettingsSMTPServer{
		listener: listener,
		messages: make(chan string, connections),
	}
	server.wg.Add(connections)
	go func() {
		for index := 0; index < connections; index++ {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				server.wg.Done()
				continue
			}
			go server.serve(connection)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		server.wg.Wait()
		close(server.messages)
	})
	return server
}

func (s *mailSettingsSMTPServer) address(t *testing.T) (string, int) {
	t.Helper()
	host, rawPort, err := net.SplitHostPort(s.listener.Addr().String())
	if err != nil {
		t.Fatalf("split mail settings SMTP address: %v", err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatalf("parse mail settings SMTP port: %v", err)
	}
	return host, port
}

func (s *mailSettingsSMTPServer) serve(connection net.Conn) {
	defer s.wg.Done()
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	writeResponse := func(response string) bool {
		if _, err := writer.WriteString(response); err != nil {
			return false
		}
		return writer.Flush() == nil
	}
	if !writeResponse("220 smtp.test ESMTP\r\n") {
		return
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(command, "EHLO"), strings.HasPrefix(command, "HELO"):
			if !writeResponse("250-smtp.test\r\n250 AUTH PLAIN\r\n") {
				return
			}
		case strings.HasPrefix(command, "AUTH PLAIN"):
			if !writeResponse("235 authentication successful\r\n") {
				return
			}
		case strings.HasPrefix(command, "MAIL FROM:"), strings.HasPrefix(command, "RCPT TO:"):
			if !writeResponse("250 accepted\r\n") {
				return
			}
		case command == "DATA":
			if !writeResponse("354 end with dot\r\n") {
				return
			}
			var message strings.Builder
			for {
				dataLine, readErr := reader.ReadString('\n')
				if readErr != nil {
					return
				}
				if dataLine == ".\r\n" || dataLine == ".\n" {
					break
				}
				message.WriteString(dataLine)
			}
			s.messages <- message.String()
			if !writeResponse("250 queued\r\n") {
				return
			}
		case command == "QUIT":
			_ = writeResponse("221 bye\r\n")
			return
		default:
			if !writeResponse("502 unsupported\r\n") {
				return
			}
		}
	}
}

func mailSettingsAdminRequest(
	method, path, body string,
	admin *models.User,
	authenticatedAt time.Time,
	event string,
) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.55:42000"
	ctx := context.WithValue(request.Context(), currentUserContextKey, admin)
	ctx = withAuthenticatedSession(ctx, &AuthenticatedSession{
		ID: "mail-settings-admin-session",
		Data: &session.SessionData{
			UserID: admin.ID.String(), Username: admin.Username,
			AuthenticatedAt: authenticatedAt, AuthVersion: admin.AuthVersion,
		},
	})
	if event != "" {
		ctx = audit.WithMutationAudit(ctx, audit.MutationAudit{
			Event: event, ActorID: admin.ID, ActorName: admin.Username,
			Result: "success", RiskLevel: "high", IPAddress: "192.0.2.55",
			UserAgent: "mail-settings-integration-test",
		})
	}
	return request.WithContext(ctx)
}

func invokeMailSettingsHandler(handler http.HandlerFunc, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	return recorder
}

func saveMailCandidateBody(revision int64, host string, port int, passwordJSON string) string {
	passwordField := ""
	if passwordJSON != "" {
		passwordField = `,"password":` + passwordJSON
	}
	return fmt.Sprintf(`{"expected_revision":%d,"host":%q,"port":%d,"username":"smtp-user"%s,"tls_mode":"plain","from_address":"noreply@example.test","from_name":"Nyauth","public_base_url":"https://auth.example.test","connect_timeout":"250ms","send_timeout":"1s"}`,
		revision, host, port, passwordField)
}

func expectSMTPTestMessage(t *testing.T, server *mailSettingsSMTPServer) {
	t.Helper()
	select {
	case message := <-server.messages:
		if !strings.Contains(message, "Subject:") || !strings.Contains(message, "Nyauth") {
			t.Fatalf("unexpected SMTP test message: %q", message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SMTP test message was not delivered")
	}
}

func TestMailSettingsHandlersRequireReauthenticationRedactSecretsAndEnforceLifecycle(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	admin := &models.User{
		ID: uuid.New(), Username: "mail-settings-admin", Status: models.UserStatusActive,
		Role: "admin", AuthVersion: 1, SessionVersion: 1, Metadata: map[string]string{},
	}
	if _, err := testApp.pool.Exec(context.Background(), `
		INSERT INTO users (id,username,status,role,auth_version,session_version,metadata,creation_source)
		VALUES ($1,$2,'active','admin',1,1,'{}'::jsonb,'legacy')
	`, admin.ID, admin.Username); err != nil {
		t.Fatalf("insert mail settings administrator: %v", err)
	}

	stale := invokeMailSettingsHandler(
		testApp.app.handleGetMailSettings,
		mailSettingsAdminRequest(http.MethodGet, "/api/admin/settings/mail", "", admin, time.Now().Add(-11*time.Minute), ""),
	)
	if stale.Code != http.StatusForbidden {
		t.Fatalf("stale mail settings status=%d body=%s", stale.Code, stale.Body.String())
	}

	smtpServer := newMailSettingsSMTPServer(t, 2)
	host, port := smtpServer.address(t)
	recent := time.Now().UTC()
	firstSecret := "first-runtime-mail-secret"
	firstSave := invokeMailSettingsHandler(
		testApp.app.handleSaveMailCandidate,
		mailSettingsAdminRequest(
			http.MethodPut, "/api/admin/settings/mail/candidate",
			saveMailCandidateBody(0, host, port, strconv.Quote(firstSecret)),
			admin, recent, models.AuditMailSettingsSaved,
		),
	)
	if firstSave.Code != http.StatusCreated {
		t.Fatalf("save first candidate status=%d body=%s", firstSave.Code, firstSave.Body.String())
	}
	if strings.Contains(firstSave.Body.String(), firstSecret) || strings.Contains(firstSave.Body.String(), "password_ciphertext") || strings.Contains(firstSave.Body.String(), `"password":`) {
		t.Fatalf("candidate response exposed password material: %s", firstSave.Body.String())
	}
	var firstCandidate struct {
		Candidate     mailConfigResponse `json:"candidate"`
		StateRevision int64              `json:"state_revision"`
	}
	if err := json.Unmarshal(firstSave.Body.Bytes(), &firstCandidate); err != nil {
		t.Fatalf("decode first candidate: %v", err)
	}
	if firstCandidate.Candidate.ID == nil || !firstCandidate.Candidate.PasswordConfigured {
		t.Fatalf("first candidate response=%#v", firstCandidate)
	}

	firstTestBody := fmt.Sprintf(`{"expected_revision":%d,"version_id":%q,"email":"operator@example.test"}`,
		firstCandidate.StateRevision, firstCandidate.Candidate.ID.String())
	firstTest := invokeMailSettingsHandler(
		testApp.app.handleTestMailCandidate,
		mailSettingsAdminRequest(http.MethodPost, "/api/admin/settings/mail/candidate/test", firstTestBody, admin, recent, models.AuditMailSettingsTested),
	)
	if firstTest.Code != http.StatusOK {
		t.Fatalf("test first candidate status=%d body=%s", firstTest.Code, firstTest.Body.String())
	}
	var firstTestResult mailTestResponse
	if err := json.Unmarshal(firstTest.Body.Bytes(), &firstTestResult); err != nil {
		t.Fatalf("decode first test result: %v", err)
	}
	if firstTestResult.Result != mailruntime.TestResultSuccess {
		t.Fatalf("first test result=%#v", firstTestResult)
	}
	expectSMTPTestMessage(t, smtpServer)

	firstActivateBody := fmt.Sprintf(`{"expected_revision":%d,"version_id":%q}`,
		firstTestResult.StateRevision, firstCandidate.Candidate.ID.String())
	firstActivate := invokeMailSettingsHandler(
		testApp.app.handleActivateMailCandidate,
		mailSettingsAdminRequest(http.MethodPost, "/api/admin/settings/mail/activate", firstActivateBody, admin, recent, models.AuditMailSettingsActivated),
	)
	if firstActivate.Code != http.StatusOK {
		t.Fatalf("activate first candidate status=%d body=%s", firstActivate.Code, firstActivate.Body.String())
	}
	var firstActivated mailMutationResponse
	if err := json.Unmarshal(firstActivate.Body.Bytes(), &firstActivated); err != nil {
		t.Fatalf("decode first activation: %v", err)
	}

	current := invokeMailSettingsHandler(
		testApp.app.handleGetMailSettings,
		mailSettingsAdminRequest(http.MethodGet, "/api/admin/settings/mail", "", admin, recent, ""),
	)
	if current.Code != http.StatusOK {
		t.Fatalf("get active settings status=%d body=%s", current.Code, current.Body.String())
	}
	if strings.Contains(current.Body.String(), firstSecret) || strings.Contains(current.Body.String(), "password_ciphertext") || strings.Contains(current.Body.String(), `"password":`) {
		t.Fatalf("active settings response exposed password material: %s", current.Body.String())
	}
	var currentSettings mailSettingsResponse
	if err := json.Unmarshal(current.Body.Bytes(), &currentSettings); err != nil {
		t.Fatalf("decode active settings: %v", err)
	}
	if currentSettings.Mode != mailruntime.ModeActive || currentSettings.Active == nil || !currentSettings.Active.PasswordConfigured {
		t.Fatalf("active settings=%#v", currentSettings)
	}

	badSave := invokeMailSettingsHandler(
		testApp.app.handleSaveMailCandidate,
		mailSettingsAdminRequest(
			http.MethodPut, "/api/admin/settings/mail/candidate",
			saveMailCandidateBody(firstActivated.StateRevision, "127.0.0.1", 1, ""),
			admin, recent, models.AuditMailSettingsSaved,
		),
	)
	if badSave.Code != http.StatusCreated {
		t.Fatalf("save failing candidate status=%d body=%s", badSave.Code, badSave.Body.String())
	}
	var badCandidate struct {
		Candidate     mailConfigResponse `json:"candidate"`
		StateRevision int64              `json:"state_revision"`
	}
	if err := json.Unmarshal(badSave.Body.Bytes(), &badCandidate); err != nil {
		t.Fatalf("decode failing candidate: %v", err)
	}
	badTestBody := fmt.Sprintf(`{"expected_revision":%d,"version_id":%q,"email":"operator@example.test"}`,
		badCandidate.StateRevision, badCandidate.Candidate.ID.String())
	badTest := invokeMailSettingsHandler(
		testApp.app.handleTestMailCandidate,
		mailSettingsAdminRequest(http.MethodPost, "/api/admin/settings/mail/candidate/test", badTestBody, admin, recent, models.AuditMailSettingsTested),
	)
	if badTest.Code != http.StatusOK {
		t.Fatalf("test failing candidate status=%d body=%s", badTest.Code, badTest.Body.String())
	}
	var badTestResult mailTestResponse
	if err := json.Unmarshal(badTest.Body.Bytes(), &badTestResult); err != nil {
		t.Fatalf("decode failing test result: %v", err)
	}
	if badTestResult.Result != mailruntime.TestResultFailure || badTestResult.ErrorCategory == nil || *badTestResult.ErrorCategory != mailruntime.ErrorCategoryTransport {
		t.Fatalf("failing test result=%#v", badTestResult)
	}
	badActivateBody := fmt.Sprintf(`{"expected_revision":%d,"version_id":%q}`,
		badTestResult.StateRevision, badCandidate.Candidate.ID.String())
	badActivate := invokeMailSettingsHandler(
		testApp.app.handleActivateMailCandidate,
		mailSettingsAdminRequest(http.MethodPost, "/api/admin/settings/mail/activate", badActivateBody, admin, recent, models.AuditMailSettingsActivated),
	)
	if badActivate.Code != http.StatusConflict {
		t.Fatalf("activate failed candidate status=%d body=%s", badActivate.Code, badActivate.Body.String())
	}

	secondSave := invokeMailSettingsHandler(
		testApp.app.handleSaveMailCandidate,
		mailSettingsAdminRequest(
			http.MethodPut, "/api/admin/settings/mail/candidate",
			saveMailCandidateBody(badTestResult.StateRevision, host, port, ""),
			admin, recent, models.AuditMailSettingsSaved,
		),
	)
	if secondSave.Code != http.StatusCreated {
		t.Fatalf("save second candidate status=%d body=%s", secondSave.Code, secondSave.Body.String())
	}
	var secondCandidate struct {
		Candidate     mailConfigResponse `json:"candidate"`
		StateRevision int64              `json:"state_revision"`
	}
	if err := json.Unmarshal(secondSave.Body.Bytes(), &secondCandidate); err != nil {
		t.Fatalf("decode second candidate: %v", err)
	}
	if !secondCandidate.Candidate.PasswordConfigured {
		t.Fatal("second candidate did not inherit the active password")
	}
	secondTestBody := fmt.Sprintf(`{"expected_revision":%d,"version_id":%q,"email":"operator@example.test"}`,
		secondCandidate.StateRevision, secondCandidate.Candidate.ID.String())
	secondTest := invokeMailSettingsHandler(
		testApp.app.handleTestMailCandidate,
		mailSettingsAdminRequest(http.MethodPost, "/api/admin/settings/mail/candidate/test", secondTestBody, admin, recent, models.AuditMailSettingsTested),
	)
	if secondTest.Code != http.StatusOK {
		t.Fatalf("test second candidate status=%d body=%s", secondTest.Code, secondTest.Body.String())
	}
	var secondTestResult mailTestResponse
	if err := json.Unmarshal(secondTest.Body.Bytes(), &secondTestResult); err != nil {
		t.Fatalf("decode second test result: %v", err)
	}
	if secondTestResult.Result != mailruntime.TestResultSuccess {
		t.Fatalf("second test result=%#v", secondTestResult)
	}
	expectSMTPTestMessage(t, smtpServer)
	secondActivateBody := fmt.Sprintf(`{"expected_revision":%d,"version_id":%q}`,
		secondTestResult.StateRevision, secondCandidate.Candidate.ID.String())
	secondActivate := invokeMailSettingsHandler(
		testApp.app.handleActivateMailCandidate,
		mailSettingsAdminRequest(http.MethodPost, "/api/admin/settings/mail/activate", secondActivateBody, admin, recent, models.AuditMailSettingsActivated),
	)
	if secondActivate.Code != http.StatusOK {
		t.Fatalf("activate second candidate status=%d body=%s", secondActivate.Code, secondActivate.Body.String())
	}
	var secondActivated mailMutationResponse
	if err := json.Unmarshal(secondActivate.Body.Bytes(), &secondActivated); err != nil {
		t.Fatalf("decode second activation: %v", err)
	}

	rollback := invokeMailSettingsHandler(
		testApp.app.handleRollbackMailSettings,
		mailSettingsAdminRequest(
			http.MethodPost, "/api/admin/settings/mail/rollback",
			fmt.Sprintf(`{"expected_revision":%d}`, secondActivated.StateRevision),
			admin, recent, models.AuditMailSettingsRolledBack,
		),
	)
	if rollback.Code != http.StatusOK {
		t.Fatalf("rollback mail settings status=%d body=%s", rollback.Code, rollback.Body.String())
	}
	var rolledBack mailMutationResponse
	if err := json.Unmarshal(rollback.Body.Bytes(), &rolledBack); err != nil {
		t.Fatalf("decode rollback: %v", err)
	}

	openRegistration := settings.DefaultRegistration()
	openRegistration.Mode = settings.RegistrationOpen
	openRegistration.RequireEmailVerification = true
	if err := setRegistrationPolicyForTest(context.Background(), testApp.app.settingsMgr, openRegistration, admin.Username, true); err != nil {
		t.Fatalf("open registration before disable conflict: %v", err)
	}
	disableBody := fmt.Sprintf(`{"expected_revision":%d}`, rolledBack.StateRevision)
	disableConflict := invokeMailSettingsHandler(
		testApp.app.handleDisableMail,
		mailSettingsAdminRequest(http.MethodPost, "/api/admin/settings/mail/disable", disableBody, admin, recent, models.AuditMailSettingsDisabled),
	)
	if disableConflict.Code != http.StatusConflict {
		t.Fatalf("disable with open registration status=%d body=%s", disableConflict.Code, disableConflict.Body.String())
	}
	if err := setRegistrationPolicyForTest(context.Background(), testApp.app.settingsMgr, settings.DefaultRegistration(), admin.Username, true); err != nil {
		t.Fatalf("close registration before disable: %v", err)
	}
	disabled := invokeMailSettingsHandler(
		testApp.app.handleDisableMail,
		mailSettingsAdminRequest(http.MethodPost, "/api/admin/settings/mail/disable", disableBody, admin, recent, models.AuditMailSettingsDisabled),
	)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable mail status=%d body=%s", disabled.Code, disabled.Body.String())
	}
	var disabledResult mailMutationResponse
	if err := json.Unmarshal(disabled.Body.Bytes(), &disabledResult); err != nil {
		t.Fatalf("decode disable result: %v", err)
	}
	if disabledResult.Status != "disabled" || testApp.app.mailManager.Status().Mode != mailruntime.ModeDisabled {
		t.Fatalf("disabled result=%#v runtime=%#v", disabledResult, testApp.app.mailManager.Status())
	}

	var auditCount int
	var auditPayload string
	if err := testApp.pool.QueryRow(context.Background(), `
		SELECT COUNT(*),COALESCE(string_agg(payload::text,''),'')
		FROM audit_event_outbox WHERE event LIKE 'mail.%'
	`).Scan(&auditCount, &auditPayload); err != nil {
		t.Fatalf("load mail audit outbox: %v", err)
	}
	if auditCount != 10 {
		t.Fatalf("mail audit event count=%d payload=%s", auditCount, auditPayload)
	}
	if strings.Contains(auditPayload, firstSecret) || strings.Contains(auditPayload, "password_ciphertext") {
		t.Fatalf("mail audit payload exposed secret material: %s", auditPayload)
	}
}
