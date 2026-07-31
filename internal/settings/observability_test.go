package settings

import (
	"testing"
	"time"
)

func TestObservabilityDefaultsAndValidation(t *testing.T) {
	value := DefaultObservability()
	if value.LogLevel != LogLevelInfo || value.Alerts.MailBacklogCount != 100 || value.MailOldestPendingDuration() != 15*time.Minute {
		t.Fatalf("observability defaults = %#v", value)
	}
	if err := ValidateObservability(value); err != nil {
		t.Fatalf("valid defaults: %v", err)
	}
	invalid := []func(*Observability){
		func(v *Observability) { v.LogLevel = "debug" },
		func(v *Observability) { v.Alerts.MailBacklogCount = 0 },
		func(v *Observability) { v.Alerts.AuditOutboxBacklogCount = MaxOperationalAlertCount + 1 },
		func(v *Observability) { v.Alerts.MailOldestPendingAge = "59s" },
		func(v *Observability) { v.Alerts.AuditOldestPendingAge = "169h" },
	}
	for index, mutate := range invalid {
		candidate := value
		mutate(&candidate)
		if err := ValidateObservability(candidate); err == nil {
			t.Fatalf("invalid candidate %d accepted: %#v", index, candidate)
		}
	}
}

func TestTemporaryDebugMustBeBounded(t *testing.T) {
	now := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	value := DefaultObservability()
	tooSoon := now.Add(30 * time.Second)
	value.DebugUntil = &tooSoon
	if err := ValidateTemporaryDebug(value, now); err == nil {
		t.Fatal("short debug window accepted")
	}
	valid := now.Add(time.Hour)
	value.DebugUntil = &valid
	if err := ValidateTemporaryDebug(value, now); err != nil {
		t.Fatalf("valid debug window: %v", err)
	}
	tooLate := now.Add(MaxTemporaryDebugDuration + time.Second)
	value.DebugUntil = &tooLate
	if err := ValidateTemporaryDebug(value, now); err == nil {
		t.Fatal("overlong debug window accepted")
	}
}
