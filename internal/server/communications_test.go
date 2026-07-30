package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

func TestEmailTemplatePreviewUsesSafeSampleDataAndFixedLink(t *testing.T) {
	manager := settings.NewManager(nil, settings.Branding{Title: "Example <Identity>"})
	server := &Server{settingsMgr: manager}
	email := account.DefaultEmailTemplateSettings()
	content := email.Templates[account.MessagePasswordReset]
	content.Body = "<strong>{{username}}</strong>"
	email.Templates[account.MessagePasswordReset] = content
	body, err := json.Marshal(emailTemplatePreviewRequest{TemplateID: account.MessagePasswordReset, Email: email})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	recorder := httptest.NewRecorder()
	server.handlePreviewEmailTemplate(recorder, httptest.NewRequest(http.MethodPost, "/api/admin/settings/communications/email/preview", strings.NewReader(string(body))))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response emailTemplatePreviewResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if strings.Contains(response.HTMLBody, "<strong>") || !strings.Contains(response.HTMLBody, "&lt;strong&gt;") {
		t.Fatalf("preview did not escape draft markup: %s", response.HTMLBody)
	}
	if !strings.Contains(response.HTMLBody, "https://example.invalid/account-action?token=preview-only") || strings.Contains(response.HTMLBody, "auth.example") {
		t.Fatalf("preview link is not the fixed inert sample: %s", response.HTMLBody)
	}
}

func TestPublicAnnouncementDefaultsToNoAnnouncementAndNoStore(t *testing.T) {
	server := &Server{settingsMgr: settings.NewManager(nil, settings.Branding{Title: "Nya"})}
	recorder := httptest.NewRecorder()
	server.handleAnnouncement(recorder, httptest.NewRequest(http.MethodGet, "/api/announcement", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache=%q", recorder.Code, recorder.Header().Get("Cache-Control"))
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["announcement"] != nil || len(response) != 1 {
		t.Fatalf("public response leaked inactive settings: %#v", response)
	}
}

func TestPublicAnnouncementExposesOnlyActivePublicFields(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	start := now.Add(-time.Hour)
	end := now.Add(time.Hour)
	response := publicAnnouncementAt(settings.Announcement{
		Version: 7, Enabled: true, Severity: settings.AnnouncementSeverityWarning,
		Title: "Planned maintenance", Message: "Sign-in remains available.",
		LinkLabel: "Status", LinkURL: "/status", Dismissible: true,
		StartsAt: &start, EndsAt: &end,
	}, now)
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	body := string(encoded)
	for _, forbidden := range []string{"enabled", "starts_at", "revision", "email", "templates"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("public announcement leaked %q: %s", forbidden, body)
		}
	}
	if response.Announcement == nil || response.Announcement.Version != 7 || response.NextChangeAt == nil || !response.NextChangeAt.Equal(end) {
		t.Fatalf("unexpected public announcement: %#v", response)
	}
}

func TestTemplateTestRecipientMustBeCurrentVerifiedAdministratorEmail(t *testing.T) {
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	manager := settings.NewManager(nil, settings.Branding{Title: "Nyauth"})
	server := &Server{
		settingsMgr:         manager,
		mailSettingsLimiter: NewMailSettingsLimiter(rdb, manager),
	}
	verifiedAt := time.Now().UTC().Add(-time.Hour)
	email := "admin@example.test"
	admin := &models.User{
		ID: uuid.New(), Username: "admin", Role: "admin",
		Status: models.UserStatusActive, Email: &email, EmailVerifiedAt: &verifiedAt,
	}
	body, err := json.Marshal(emailTemplateTestRequest{
		TemplateID: account.MessagePasswordReset,
		Recipient:  "other@example.test",
		Email:      account.DefaultEmailTemplateSettings(),
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/admin/settings/communications/email/test", strings.NewReader(string(body)))
	request.RemoteAddr = "192.0.2.22:42000"
	ctx := context.WithValue(request.Context(), currentUserContextKey, admin)
	ctx = withAuthenticatedSession(ctx, &AuthenticatedSession{Data: &session.SessionData{
		UserID: admin.ID.String(), Username: admin.Username, AuthenticatedAt: time.Now().UTC(),
	}})
	ctx = audit.WithMutationAudit(ctx, audit.MutationAudit{
		Event: models.AuditMailTemplateTested, ActorID: admin.ID, ActorName: admin.Username,
		Result: "success", RiskLevel: "high",
	})
	recorder := httptest.NewRecorder()
	server.handleTestEmailTemplate(recorder, request.WithContext(ctx))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "must match") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAnnouncementStreamLimitFailsBeforeStartingSSE(t *testing.T) {
	server := &Server{settingsMgr: settings.NewManager(nil, settings.Branding{Title: "Nya"})}
	server.announcementStreams.Store(maxAnnouncementEventStreams)
	recorder := httptest.NewRecorder()
	server.handleAnnouncementEvents(recorder, httptest.NewRequest(http.MethodGet, announcementEventsPath, nil))
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") != "30" {
		t.Fatalf("status=%d retry=%q body=%s", recorder.Code, recorder.Header().Get("Retry-After"), recorder.Body.String())
	}
}

func TestMailActionPublicURLMustRemainOnIssuerOrigin(t *testing.T) {
	for _, test := range []struct {
		left, right string
		want        bool
	}{
		{"https://auth.example.test/mail/path", "https://auth.example.test", true},
		{"https://AUTH.example.test", "https://auth.example.test/issuer", true},
		{"https://attacker.example.test", "https://auth.example.test", false},
		{"http://auth.example.test", "https://auth.example.test", false},
		{"https://user:secret@auth.example.test", "https://auth.example.test", false},
	} {
		if got := sameHTTPOrigin(test.left, test.right); got != test.want {
			t.Fatalf("sameHTTPOrigin(%q,%q)=%v want %v", test.left, test.right, got, test.want)
		}
	}
}
