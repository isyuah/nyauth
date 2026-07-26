package audit

import (
	"testing"
	"time"
)

func TestAuditPartitionNamingUsesUTCMonth(t *testing.T) {
	instant := time.Date(2026, time.August, 1, 0, 30, 0, 0, time.FixedZone("UTC+8", 8*60*60))
	if got := auditPartitionName(instant); got != "audit_logs_2026_07" {
		t.Fatalf("partition name = %q, want audit_logs_2026_07", got)
	}
	if got := quoteAuditPartitionBoundary(auditMonthStart(instant)); got != "TIMESTAMPTZ '2026-07-01T00:00:00Z'" {
		t.Fatalf("partition boundary = %q", got)
	}
}

func TestParseAuditPartitionNameRejectsUnexpectedIdentifiers(t *testing.T) {
	valid, ok := parseAuditPartitionName("audit_logs_2026_07")
	if !ok || valid.Year() != 2026 || valid.Month() != time.July {
		t.Fatalf("valid partition was rejected: %v %v", valid, ok)
	}
	for _, value := range []string{
		"audit_logs_2026_7",
		"audit_logs_2026_13",
		"audit_logs_default",
		"audit_logs_2026_07;DROP TABLE users",
	} {
		if _, ok := parseAuditPartitionName(value); ok {
			t.Fatalf("unexpected partition name accepted: %q", value)
		}
	}
}
