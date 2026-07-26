package models

import "time"

// DashboardStats is the bounded, periodically refreshed administrative
// overview. Registration completion rate is nil when the 30-day cohort is
// empty rather than being reported as a misleading zero percent.
type DashboardStats struct {
	UserCount                     int64     `json:"user_count"`
	AppCount                      int64     `json:"app_count"`
	LoginCount7d                  int64     `json:"login_count_7d"`
	ActiveSessions                int64     `json:"active_sessions"`
	FailedLogins7d                int64     `json:"failed_logins_7d"`
	PendingRegistrations          int64     `json:"pending_registrations"`
	CompletedRegistrations7d      int64     `json:"completed_registrations_7d"`
	RegistrationCompletionRate30d *float64  `json:"registration_completion_rate_30d"`
	MailBacklog                   int64     `json:"mail_backlog"`
	MailFailures24h               int64     `json:"mail_failures_24h"`
	SMTPCircuitState              string    `json:"smtp_circuit_state"`
	MailStatsAvailableFrom        time.Time `json:"mail_stats_available_from"`
	RefreshedAt                   time.Time `json:"refreshed_at"`
}

// LoginTrend holds login trend data for the existing single-series chart.
type LoginTrend struct {
	Labels []string `json:"labels"`
	Values []int64  `json:"values"`
}

type RegistrationTrendPoint struct {
	Day                    string `json:"day"`
	RegistrationsStarted   int64  `json:"registrations_started"`
	RegistrationsCompleted int64  `json:"registrations_completed"`
	RegistrationsExpired   int64  `json:"registrations_expired"`
	InvitesReserved        int64  `json:"invites_reserved"`
	InvitesConsumed        int64  `json:"invites_consumed"`
	InvitesReleased        int64  `json:"invites_released"`
}

type RegistrationTrend struct {
	Timezone string                   `json:"timezone"`
	Points   []RegistrationTrendPoint `json:"points"`
}

type MailTrendPoint struct {
	Day           string `json:"day"`
	Enqueued      int64  `json:"enqueued"`
	Sent          int64  `json:"sent"`
	OtherFailures int64  `json:"other_failures"`
	Rejected      int64  `json:"rejected"`
	Expired       int64  `json:"expired"`
}

type MailTrend struct {
	Timezone      string           `json:"timezone"`
	AvailableFrom time.Time        `json:"available_from"`
	Points        []MailTrendPoint `json:"points"`
}

// RecentLogin holds a recent login entry for the dashboard.
type RecentLogin struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Result   string `json:"result"`
	IP       string `json:"ip"`
	Time     string `json:"time"`
}
