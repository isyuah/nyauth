package audit

import (
	"strings"
	"testing"
	"time"
)

func TestBuildListFilterUsesBoundParameters(t *testing.T) {
	from := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	where, args := buildListFilter(ListFilter{
		Event: "user.login", Result: "success", RiskLevel: "low",
		Actor: "alice", Target: "client", IPAddress: "192.0.2.1",
		CreatedFrom: &from, CreatedTo: &to,
	})
	for _, fragment := range []string{"event = $1", "result = $2", "risk_level = $3", "actor_name ILIKE", "actor_id::text = $4", "target_id ILIKE", "target_type ILIKE", "ip_address = $6", "created_at >= $7", "created_at <= $8"} {
		if !strings.Contains(where, fragment) {
			t.Fatalf("filter %q missing from %q", fragment, where)
		}
	}
	if len(args) != 8 {
		t.Fatalf("argument count = %d, want 8", len(args))
	}
}

func TestBuildListFilterEmpty(t *testing.T) {
	where, args := buildListFilter(ListFilter{})
	if where != "" || len(args) != 0 {
		t.Fatalf("empty filter returned where=%q args=%v", where, args)
	}
}
