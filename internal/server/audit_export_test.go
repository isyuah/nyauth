package server

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestAuditExportFilterAppliesBoundedDefaultWindow(t *testing.T) {
	now := time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC)
	subject := uuid.MustParse("35f7d711-78c3-42ec-a73a-0a4ae197504c")
	request := httptest.NewRequest("GET", "/api/admin/audit-logs/export?event=user.login&subject_user_id="+subject.String()+"&target_type=user&target_id=target-1", nil)
	filter, err := auditExportFilter(request, now)
	if err != nil {
		t.Fatalf("auditExportFilter() error = %v", err)
	}
	if filter.Event != "user.login" || filter.SubjectUserID == nil || *filter.SubjectUserID != subject ||
		filter.TargetType != "user" || filter.TargetID != "target-1" || filter.CreatedFrom == nil || filter.CreatedTo == nil {
		t.Fatalf("unexpected filter: %#v", filter)
	}
	if !filter.CreatedFrom.Equal(now.Add(-24*time.Hour)) || !filter.CreatedTo.Equal(now) {
		t.Fatalf("default window = %v to %v", filter.CreatedFrom, filter.CreatedTo)
	}
}

func TestAuditExportFilterRejectsOversizedOrReversedWindow(t *testing.T) {
	now := time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC)
	for _, target := range []string{
		"/api/admin/audit-logs/export?from=2026-06-01T00%3A00%3A00Z&to=2026-07-26T00%3A00%3A00Z",
		"/api/admin/audit-logs/export?from=2026-07-27T00%3A00%3A00Z&to=2026-07-26T00%3A00%3A00Z",
	} {
		if _, err := auditExportFilter(httptest.NewRequest("GET", target, nil), now); err == nil {
			t.Fatalf("oversized or reversed range accepted: %s", target)
		}
	}
}

func TestAuditLogCEFEscapesUntrustedValues(t *testing.T) {
	actor := "alice=admin\nforged"
	targetType := "user"
	targetID := `id\\=42`
	entry := models.AuditLog{
		ID:    uuid.MustParse("b9f163b4-52d7-4140-b5ac-751ec42dfe39"),
		Event: "user.role|changed", ActorName: &actor, TargetType: &targetType, TargetID: &targetID,
		Result: "success", RiskLevel: "high", CreatedAt: time.Unix(1_700_000_000, 0).UTC(),
	}
	encoded := auditLogCEF(entry)
	for _, expected := range []string{`user.role\|changed`, `suser=alice\=admin\nforged`, `duser=user:id\\\\\=42`, `|8|`} {
		if !strings.Contains(encoded, expected) {
			t.Fatalf("CEF output %q does not contain %q", encoded, expected)
		}
	}
}
