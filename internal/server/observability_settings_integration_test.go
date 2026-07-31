package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/observabilityruntime"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestObservabilitySettingsHandlersRedactSecretsAndActivateTestedCandidate(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	admin := &models.User{ID: uuid.New(), Username: "telemetry-admin", Status: models.UserStatusActive, Role: "admin", AuthVersion: 1, SessionVersion: 1, Metadata: map[string]string{}}
	if _, err := testApp.pool.Exec(t.Context(), `INSERT INTO users (id,username,status,role,auth_version,session_version,metadata,creation_source) VALUES ($1,$2,'active','admin',1,1,'{}'::jsonb,'legacy')`, admin.ID, admin.Username); err != nil {
		t.Fatal(err)
	}
	recent := time.Now().UTC()

	policy := settings.DefaultObservability()
	policy.LogLevel = settings.LogLevelWarn
	policy.Alerts.MailBacklogCount = 42
	encodedPolicy, _ := json.Marshal(map[string]any{"expected_revision": 0, "observability": policy})
	update := invokeMailSettingsHandler(testApp.app.handleUpdateObservabilitySettings, mailSettingsAdminRequest(http.MethodPut, "/api/admin/settings/observability", string(encodedPolicy), admin, recent, models.AuditSettingsUpdated))
	if update.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", update.Code, update.Body.String())
	}
	if testApp.app.settingsMgr.ObservabilitySnapshot().Revision != 1 || testApp.app.settingsMgr.Observability().LogLevel != settings.LogLevelWarn {
		t.Fatalf("stored policy=%#v", testApp.app.settingsMgr.ObservabilitySnapshot())
	}

	var requests atomic.Int64
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/v1/metrics" || r.Header.Get("Authorization") != "Bearer collector-secret" {
			t.Errorf("request path=%q authorization=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()
	defer func() {
		if err := testApp.app.telemetry.DisableOTLP(t.Context()); err != nil {
			t.Errorf("disable test OTLP exporter: %v", err)
		}
	}()
	secret := "Bearer collector-secret"
	candidateBody := fmt.Sprintf(`{"expected_revision":0,"endpoint":%q,"authorization":%q,"export_interval":"10s","timeout":"2s"}`, collector.URL+"/v1/metrics", secret)
	saved := invokeMailSettingsHandler(testApp.app.handleSaveOTLPCandidate, mailSettingsAdminRequest(http.MethodPut, "/api/admin/settings/observability/otlp/candidate", candidateBody, admin, recent, models.AuditTelemetrySettingsSaved))
	if saved.Code != http.StatusCreated {
		t.Fatalf("save status=%d body=%s", saved.Code, saved.Body.String())
	}
	if strings.Contains(saved.Body.String(), secret) || strings.Contains(saved.Body.String(), "ciphertext") {
		t.Fatalf("candidate leaked secret: %s", saved.Body.String())
	}
	var candidate struct {
		Candidate     otlpConfigResponse `json:"candidate"`
		StateRevision int64              `json:"state_revision"`
	}
	if err := json.Unmarshal(saved.Body.Bytes(), &candidate); err != nil || candidate.Candidate.ID == nil {
		t.Fatalf("candidate=%#v err=%v", candidate, err)
	}

	testBody := fmt.Sprintf(`{"expected_revision":%d,"version_id":%q}`, candidate.StateRevision, candidate.Candidate.ID.String())
	tested := invokeMailSettingsHandler(testApp.app.handleTestOTLPCandidate, mailSettingsAdminRequest(http.MethodPost, "/api/admin/settings/observability/otlp/candidate/test", testBody, admin, recent, models.AuditTelemetrySettingsTested))
	if tested.Code != http.StatusOK || !strings.Contains(tested.Body.String(), `"result":"success"`) {
		t.Fatalf("test status=%d body=%s", tested.Code, tested.Body.String())
	}
	if requests.Load() < 1 {
		t.Fatal("collector did not receive test metric")
	}
	var testResult struct {
		StateRevision int64 `json:"state_revision"`
	}
	if err := json.Unmarshal(tested.Body.Bytes(), &testResult); err != nil {
		t.Fatal(err)
	}

	getCandidate := invokeMailSettingsHandler(testApp.app.handleGetObservabilitySettings, mailSettingsAdminRequest(http.MethodGet, "/api/admin/settings/observability", "", admin, recent, ""))
	if getCandidate.Code != http.StatusOK {
		t.Fatalf("candidate GET status=%d body=%s", getCandidate.Code, getCandidate.Body.String())
	}
	var candidateSettings observabilitySettingsResponse
	if err := json.Unmarshal(getCandidate.Body.Bytes(), &candidateSettings); err != nil {
		t.Fatal(err)
	}
	if candidateSettings.OTLP.CandidateTest == nil || !candidateSettings.OTLP.CandidateTest.ActivationEligible || candidateSettings.OTLP.CandidateTest.ValidUntil == nil {
		t.Fatalf("candidate test evidence=%#v", candidateSettings.OTLP.CandidateTest)
	}

	activateBody := fmt.Sprintf(`{"expected_revision":%d,"version_id":%q}`, testResult.StateRevision, candidate.Candidate.ID.String())
	activated := invokeMailSettingsHandler(testApp.app.handleActivateOTLPCandidate, mailSettingsAdminRequest(http.MethodPost, "/api/admin/settings/observability/otlp/activate", activateBody, admin, recent, models.AuditTelemetrySettingsActivated))
	if activated.Code != http.StatusOK {
		t.Fatalf("activate status=%d body=%s", activated.Code, activated.Body.String())
	}

	get := invokeMailSettingsHandler(testApp.app.handleGetObservabilitySettings, mailSettingsAdminRequest(http.MethodGet, "/api/admin/settings/observability", "", admin, recent, ""))
	if get.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", get.Code, get.Body.String())
	}
	if strings.Contains(get.Body.String(), secret) || strings.Contains(get.Body.String(), "authorization_ciphertext") {
		t.Fatalf("GET leaked authorization: %s", get.Body.String())
	}
	var response observabilitySettingsResponse
	if err := json.Unmarshal(get.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.OTLP.Mode != observabilityruntime.ModeActive || response.OTLP.Active == nil || !response.OTLP.Active.AuthorizationConfigured {
		t.Fatalf("OTLP response=%#v", response.OTLP)
	}
}
