package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/pkg/models"
)

func mediaSettingsAdminRequest(method, path, body string, admin *models.User, authenticatedAt time.Time, event string) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.81:43000"
	ctx := context.WithValue(request.Context(), currentUserContextKey, admin)
	ctx = withAuthenticatedSession(ctx, &AuthenticatedSession{
		ID: "media-settings-admin-session",
		Data: &session.SessionData{
			UserID: admin.ID.String(), Username: admin.Username,
			AuthenticatedAt: authenticatedAt, AuthVersion: admin.AuthVersion,
		},
	})
	if event != "" {
		ctx = audit.WithMutationAudit(ctx, audit.MutationAudit{
			Event: event, ActorID: admin.ID, ActorName: admin.Username,
			Result: "success", RiskLevel: "critical", IPAddress: "192.0.2.81",
			UserAgent: "media-settings-integration-test",
		})
	}
	return request.WithContext(ctx)
}

func invokeMediaSettingsHandler(handler http.HandlerFunc, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	return recorder
}

func TestMediaSettingsHandlersRequireReauthenticationRedactCredentialsAndEnforceCAS(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	admin := &models.User{
		ID: uuid.New(), Username: "media-settings-admin", Status: models.UserStatusActive,
		Role: "admin", AuthVersion: 1, SessionVersion: 1, Metadata: map[string]string{},
	}
	if _, err := testApp.pool.Exec(context.Background(), `
		INSERT INTO users (id,username,status,role,auth_version,session_version,metadata,creation_source)
		VALUES ($1,$2,'active','admin',1,1,'{}'::jsonb,'legacy')
	`, admin.ID, admin.Username); err != nil {
		t.Fatalf("insert media settings administrator: %v", err)
	}

	stale := invokeMediaSettingsHandler(
		testApp.app.handleGetMediaSettings,
		mediaSettingsAdminRequest(http.MethodGet, "/api/admin/settings/media", "", admin, time.Now().Add(-11*time.Minute), ""),
	)
	if stale.Code != http.StatusForbidden {
		t.Fatalf("stale media settings status=%d body=%s", stale.Code, stale.Body.String())
	}

	recent := time.Now().UTC()
	initial := invokeMediaSettingsHandler(
		testApp.app.handleGetMediaSettings,
		mediaSettingsAdminRequest(http.MethodGet, "/api/admin/settings/media", "", admin, recent, ""),
	)
	if initial.Code != http.StatusOK || !strings.Contains(initial.Body.String(), `"mode":"fallback"`) {
		t.Fatalf("initial media settings status=%d body=%s", initial.Code, initial.Body.String())
	}

	accessKey, secretKey, sessionToken := "runtime-access-key", "runtime-secret-key", "runtime-session-token"
	body, err := json.Marshal(map[string]any{
		"expected_revision": 1,
		"endpoint":          "https://s3.example.test",
		"region":            "auto",
		"bucket":            "private-media",
		"prefix":            "nyauth",
		"path_style":        true,
		"access_key_id":     accessKey,
		"secret_access_key": secretKey,
		"session_token":     sessionToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	saved := invokeMediaSettingsHandler(
		testApp.app.handleSaveMediaCandidate,
		mediaSettingsAdminRequest(http.MethodPut, "/api/admin/settings/media/candidate", string(body), admin, recent, models.AuditMediaSettingsSaved),
	)
	if saved.Code != http.StatusCreated {
		t.Fatalf("save media candidate status=%d body=%s", saved.Code, saved.Body.String())
	}
	for _, secret := range []string{accessKey, secretKey, sessionToken, "encrypted_access_key_id", "encrypted_secret_access_key"} {
		if strings.Contains(saved.Body.String(), secret) {
			t.Fatalf("media candidate response exposed credential material %q: %s", secret, saved.Body.String())
		}
	}
	if !strings.Contains(saved.Body.String(), `"credentials_configured":true`) || !strings.Contains(saved.Body.String(), `"session_token_configured":true`) {
		t.Fatalf("media candidate response omitted credential presence flags: %s", saved.Body.String())
	}

	conflict := invokeMediaSettingsHandler(
		testApp.app.handleSaveMediaCandidate,
		mediaSettingsAdminRequest(http.MethodPut, "/api/admin/settings/media/candidate", string(body), admin, recent, models.AuditMediaSettingsSaved),
	)
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), `"code":"media.revision_conflict"`) {
		t.Fatalf("stale media candidate status=%d body=%s", conflict.Code, conflict.Body.String())
	}
}
