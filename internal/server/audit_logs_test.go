package server

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestAuditLogFilterFromRequestParsesExactSubjectAndTarget(t *testing.T) {
	subject := uuid.MustParse("aef64038-08ec-4c94-8129-e568664b05d8")
	request := httptest.NewRequest("GET", "/api/admin/audit-logs?subject_user_id="+subject.String()+
		"&target_type=user&target_id=target-42&from=2026-07-01T08%3A00%3A00%2B08%3A00&to=2026-07-02T00%3A00%3A00Z", nil)
	filter, err := auditLogFilterFromRequest(request)
	if err != nil {
		t.Fatalf("auditLogFilterFromRequest() error = %v", err)
	}
	if filter.SubjectUserID == nil || *filter.SubjectUserID != subject {
		t.Fatalf("subject user = %v", filter.SubjectUserID)
	}
	if filter.TargetType != "user" || filter.TargetID != "target-42" {
		t.Fatalf("exact target = %q/%q", filter.TargetType, filter.TargetID)
	}
	if filter.CreatedFrom == nil || !filter.CreatedFrom.Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("created from = %v", filter.CreatedFrom)
	}
}

func TestAuditLogFilterFromRequestRejectsInvalidSubjectOrRange(t *testing.T) {
	for _, target := range []string{
		"/api/admin/audit-logs?subject_user_id=not-a-uuid",
		"/api/admin/audit-logs?from=2026-07-02T00%3A00%3A00Z&to=2026-07-01T00%3A00%3A00Z",
	} {
		if _, err := auditLogFilterFromRequest(httptest.NewRequest("GET", target, nil)); err == nil {
			t.Fatalf("invalid audit filter accepted: %s", target)
		}
	}
}

func TestAdminAuditLogFromModelIncludesUserAgentAndRedactsDetails(t *testing.T) {
	userAgent := "ExampleBrowser/1.0"
	item := adminAuditLogFromModel(models.AuditLog{
		ID: uuid.New(), Event: models.AuditUserLogin, UserAgent: &userAgent,
		Details: map[string]interface{}{
			"method": "password",
			"nested": map[string]interface{}{"refresh_token": "legacy-secret"},
		},
	})
	if item.UserAgent == nil || *item.UserAgent != userAgent {
		t.Fatalf("user agent = %v", item.UserAgent)
	}
	if item.Details["method"] != "password" {
		t.Fatalf("safe details missing: %#v", item.Details)
	}
	nested := item.Details["nested"].(map[string]interface{})
	if nested["refresh_token"] != "[REDACTED]" {
		t.Fatalf("nested details not redacted: %#v", nested)
	}
}

func TestHandleAuditLogOptionsReturnsNoStoreCatalog(t *testing.T) {
	recorder := httptest.NewRecorder()
	(&Server{}).handleAuditLogOptions(recorder, httptest.NewRequest("GET", "/api/admin/audit-logs/options", nil))
	if recorder.Code != 200 {
		t.Fatalf("status = %d", recorder.Code)
	}
	if recorder.Header().Get("Cache-Control") != "no-store, private" {
		t.Fatalf("cache control = %q", recorder.Header().Get("Cache-Control"))
	}
	for _, expected := range []string{`"events"`, `"results"`, `"risks"`, `"target_types"`} {
		if body := recorder.Body.String(); !strings.Contains(body, expected) {
			t.Fatalf("options response %q missing %s", body, expected)
		}
	}
}
