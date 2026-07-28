package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBuildListFilterUsesBoundParameters(t *testing.T) {
	from := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	subjectUserID := uuid.New()
	where, args := buildListFilter(ListFilter{
		Events: []string{"user.login", "user.logout"}, Result: "success", RiskLevel: "low",
		Actor: "alice", Target: "client", IPAddress: "192.0.2.1",
		SubjectUserID: &subjectUserID,
		CreatedFrom:   &from, CreatedTo: &to,
	})
	for _, fragment := range []string{
		"event = ANY($1::text[])", "result = $2", "risk_level = $3", "actor_name ILIKE",
		"actor_id::text = $4", "target_id ILIKE", "target_type ILIKE", "ip_address = $6",
		"actor_id = $7", "target_type = 'user'", "target_id = $7::text",
		"created_at >= $8", "created_at <= $9",
	} {
		if !strings.Contains(where, fragment) {
			t.Fatalf("filter %q missing from %q", fragment, where)
		}
	}
	if len(args) != 9 || args[6] != subjectUserID {
		t.Fatalf("arguments = %#v, want subject user at position 7", args)
	}
}

func TestBuildListFilterEmpty(t *testing.T) {
	where, args := buildListFilter(ListFilter{})
	if where != "" || len(args) != 0 {
		t.Fatalf("empty filter returned where=%q args=%v", where, args)
	}
}

func TestBuildListFilterUsesExactTargetFilters(t *testing.T) {
	where, args := buildListFilter(ListFilter{TargetType: "user", TargetID: "user-123"})
	if !strings.Contains(where, "target_type = $1") || !strings.Contains(where, "target_id = $2") {
		t.Fatalf("exact target filter missing from %q", where)
	}
	if len(args) != 2 || args[0] != "user" || args[1] != "user-123" {
		t.Fatalf("arguments = %#v", args)
	}
}
