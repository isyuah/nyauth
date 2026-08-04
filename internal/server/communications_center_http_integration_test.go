package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/notification"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestCommunicationsCenterHTTPWorkflow(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	ctx := context.Background()
	displayName := "Announcement Admin"
	admin := &models.User{
		ID: uuid.New(), Username: "announcement-http-admin", DisplayName: &displayName,
		Status: models.UserStatusActive, Role: "admin", AuthVersion: 1, SessionVersion: 1,
		Metadata: map[string]string{},
	}
	if err := user.NewStore(testApp.pool).Create(ctx, admin); err != nil {
		t.Fatal(err)
	}
	authenticated, cookie := createDeviceTestSession(t, testApp.app, admin)

	withoutCSRF := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/admin/announcements", `{"title":"blocked"}`, cookie, "")
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("create without CSRF status=%d body=%s", withoutCSRF.Code, withoutCSRF.Body.String())
	}

	preview := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/admin/announcements/preview", `{"body_markdown":"Safe **preview**"}`, cookie, authenticated.Data.CSRFToken)
	var previewResponse struct {
		BodyHTML string `json:"body_html"`
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &previewResponse); err != nil {
		t.Fatalf("decode preview response: %v", err)
	}
	if preview.Code != http.StatusOK || preview.Header().Get("Cache-Control") != "no-store" || !strings.Contains(previewResponse.BodyHTML, "<strong>preview</strong>") {
		t.Fatalf("preview status=%d cache=%q body=%s", preview.Code, preview.Header().Get("Cache-Control"), preview.Body.String())
	}

	created := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/admin/announcements", `{
		"severity":"warning","audience":"authenticated","title":"Security update",
		"summary":"Review recent sessions","body_markdown":"Open the **security center**.",
		"link_url":"/profile/security","pinned":true,"starts_at":null,"ends_at":null
	}`, cookie, authenticated.Data.CSRFToken)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var draft notification.Announcement
	if err := json.Unmarshal(created.Body.Bytes(), &draft); err != nil {
		t.Fatal(err)
	}

	published := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/admin/announcements/"+draft.ID.String()+"/publish", `{"expected_revision":1}`, cookie, authenticated.Data.CSRFToken)
	if published.Code != http.StatusOK {
		t.Fatalf("publish status=%d body=%s", published.Code, published.Body.String())
	}
	var publicRevision notification.Announcement
	if err := json.Unmarshal(published.Body.Bytes(), &publicRevision); err != nil {
		t.Fatal(err)
	}

	listed := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/announcements?page=1&page_size=20", "", cookie, "")
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), "body_markdown") || strings.Contains(listed.Body.String(), "created_by") {
		t.Fatalf("public list status=%d body=%s", listed.Code, listed.Body.String())
	}
	if strings.Contains(listed.Body.String(), "body_html") {
		t.Fatalf("public list included full announcement body: %s", listed.Body.String())
	}
	detail := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/announcements/"+draft.ID.String(), "", cookie, "")
	var publicDetail notification.Announcement
	if err := json.Unmarshal(detail.Body.Bytes(), &publicDetail); err != nil {
		t.Fatalf("decode public detail: %v", err)
	}
	if detail.Code != http.StatusOK || !strings.Contains(publicDetail.BodyHTML, "<strong>security center</strong>") || strings.Contains(detail.Body.String(), "body_markdown") {
		t.Fatalf("public detail status=%d body=%s", detail.Code, detail.Body.String())
	}

	read := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/announcements/"+draft.ID.String()+"/read", "", cookie, authenticated.Data.CSRFToken)
	if read.Code != http.StatusNoContent {
		t.Fatalf("mark read status=%d body=%s", read.Code, read.Body.String())
	}
	count := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/notifications/unread-count", "", cookie, "")
	if count.Code != http.StatusOK || !strings.Contains(count.Body.String(), `"announcement_count":0`) {
		t.Fatalf("unread count status=%d body=%s", count.Code, count.Body.String())
	}
	if err := testApp.app.notificationStore.CreateNotification(ctx, notification.NotificationInput{
		UserID: admin.ID, Type: notification.TypePasswordChanged, Severity: notification.SeverityWarning,
		Title: "Password changed", BodyMarkdown: "Review **security settings**.", LinkURL: "/profile/security",
		SourceType: "user", SourceID: admin.ID.String(),
	}); err != nil {
		t.Fatalf("create personal notification: %v", err)
	}
	notifications := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/notifications", "", cookie, "")
	var notificationPage models.PaginatedResponse[notification.Notification]
	if err := json.Unmarshal(notifications.Body.Bytes(), &notificationPage); err != nil {
		t.Fatalf("decode notifications: %v", err)
	}
	if notifications.Code != http.StatusOK || len(notificationPage.Items) != 1 || !strings.Contains(notificationPage.Items[0].BodyHTML, "<strong>security settings</strong>") || strings.Contains(notifications.Body.String(), "body_markdown") {
		t.Fatalf("notification list status=%d body=%s", notifications.Code, notifications.Body.String())
	}
	messageCenter := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/messages?read=unread&severity=warning&page=1&page_size=20", "", cookie, "")
	var messagePage models.PaginatedResponse[notification.MessageCenterItem]
	if err := json.Unmarshal(messageCenter.Body.Bytes(), &messagePage); err != nil {
		t.Fatalf("decode message center: %v", err)
	}
	if messageCenter.Code != http.StatusOK || messagePage.Total != 1 || len(messagePage.Items) != 1 || messagePage.Items[0].Kind != notification.MessageKindNotification {
		t.Fatalf("message center status=%d body=%s", messageCenter.Code, messageCenter.Body.String())
	}
	invalidMessages := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/messages?kind=unknown", "", cookie, "")
	if invalidMessages.Code != http.StatusBadRequest {
		t.Fatalf("invalid message filter status=%d body=%s", invalidMessages.Code, invalidMessages.Body.String())
	}
	readAllMessages := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/messages/read-all?kind=notification", "", cookie, authenticated.Data.CSRFToken)
	if readAllMessages.Code != http.StatusNoContent {
		t.Fatalf("mark category read status=%d body=%s", readAllMessages.Code, readAllMessages.Body.String())
	}
	count = mfaHTTPRequest(testApp.app, http.MethodGet, "/api/notifications/unread-count", "", cookie, "")
	if count.Code != http.StatusOK || !strings.Contains(count.Body.String(), `"unread_count":0`) {
		t.Fatalf("message count after category read status=%d body=%s", count.Code, count.Body.String())
	}

	republished := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/admin/announcements/"+draft.ID.String()+"/publish", `{"expected_revision":`+strconv.FormatInt(publicRevision.Revision, 10)+`}`, cookie, authenticated.Data.CSRFToken)
	if republished.Code != http.StatusConflict || !strings.Contains(republished.Body.String(), `"code":"announcement.invalid_transition"`) {
		t.Fatalf("republish status=%d body=%s", republished.Code, republished.Body.String())
	}
	missingRevision := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/admin/announcements/"+draft.ID.String()+"/archive", `{}`, cookie, authenticated.Data.CSRFToken)
	if missingRevision.Code != http.StatusBadRequest {
		t.Fatalf("archive without revision status=%d body=%s", missingRevision.Code, missingRevision.Body.String())
	}
}
