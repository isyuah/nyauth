package stats

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

const (
	statsRefreshLockID = int64(0x4e5953544154) // "NYSTAT"
	statsHistoryDays   = 90
)

// Handler handles stats API endpoints.
type Handler struct {
	db       *pgxpool.Pool
	sessions *session.Store
}

// NewHandler creates a new stats handler.
func NewHandler(db *pgxpool.Pool, rdb *redis.Client) *Handler {
	return &Handler{db: db, sessions: session.NewStore(rdb)}
}

// GetStats returns system-wide statistics.
func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stats := models.DashboardStats{}
	var registrationsStarted30d, registrationsCompleted30d int64
	if err := h.db.QueryRow(ctx, `
		SELECT snapshot.user_count, snapshot.app_count, snapshot.active_sessions,
		       snapshot.login_count_7d, snapshot.failed_logins_7d,
		       snapshot.pending_registrations, snapshot.completed_registrations_7d,
		       snapshot.registration_started_30d, snapshot.registration_completed_30d,
		       snapshot.mail_backlog, snapshot.mail_failures_24h,
		       snapshot.smtp_circuit_state, state.mail_stats_available_from,
		       snapshot.refreshed_at
		FROM system_stats_snapshot AS snapshot
		CROSS JOIN stats_observability_state AS state
		WHERE snapshot.singleton = TRUE AND state.singleton = TRUE
	`).Scan(
		&stats.UserCount, &stats.AppCount, &stats.ActiveSessions,
		&stats.LoginCount7d, &stats.FailedLogins7d,
		&stats.PendingRegistrations, &stats.CompletedRegistrations7d,
		&registrationsStarted30d, &registrationsCompleted30d,
		&stats.MailBacklog, &stats.MailFailures24h,
		&stats.SMTPCircuitState, &stats.MailStatsAvailableFrom, &stats.RefreshedAt,
	); err != nil {
		status := http.StatusInternalServerError
		if err == pgx.ErrNoRows {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]string{"error": "statistics are not available"})
		return
	}
	if registrationsStarted30d > 0 {
		rate := float64(registrationsCompleted30d) / float64(registrationsStarted30d)
		stats.RegistrationCompletionRate30d = &rate
	}

	writeJSON(w, http.StatusOK, stats)
}

// GetLoginTrend returns login counts per day for the last N days.
func (h *Handler) GetLoginTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	days := 7
	if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d > 0 && d <= 90 {
		days = d
	}

	today := utcDay(time.Now())
	start := today.AddDate(0, 0, -(days - 1))
	counts := make(map[string]int64, days)
	rows, err := h.db.Query(ctx, `
		SELECT day, successful_logins
		FROM login_stats_daily
		WHERE day >= $1 AND day <= $2
		ORDER BY day
	`, start, today)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load login trend"})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var day time.Time
		var count int64
		if err := rows.Scan(&day, &count); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load login trend"})
			return
		}
		counts[day.UTC().Format("2006-01-02")] = count
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load login trend"})
		return
	}

	trend := models.LoginTrend{}
	for i := days - 1; i >= 0; i-- {
		day := today.AddDate(0, 0, -i)
		label := day.Format("01-02")
		trend.Labels = append(trend.Labels, label)
		trend.Values = append(trend.Values, counts[day.Format("2006-01-02")])
	}

	writeJSON(w, http.StatusOK, trend)
}

// GetRegistrationTrend returns zero-filled UTC daily registration and invite
// lifecycle aggregates. Explicit invalid ranges are rejected instead of being
// silently replaced, which keeps dashboards and automation honest.
func (h *Handler) GetRegistrationTrend(w http.ResponseWriter, r *http.Request) {
	days, err := parseTrendDays(r, 30)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	today := utcDay(time.Now())
	start := today.AddDate(0, 0, -(days - 1))
	rows, err := h.db.Query(r.Context(), `
		SELECT day,registrations_started,registrations_completed,registrations_expired,
		       invites_reserved,invites_consumed,invites_released
		FROM registration_stats_daily
		WHERE day >= $1 AND day <= $2
		ORDER BY day
	`, start, today)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load registration trend"})
		return
	}
	defer rows.Close()
	pointsByDay := make(map[string]models.RegistrationTrendPoint, days)
	for rows.Next() {
		var day time.Time
		var point models.RegistrationTrendPoint
		if err := rows.Scan(
			&day, &point.RegistrationsStarted, &point.RegistrationsCompleted, &point.RegistrationsExpired,
			&point.InvitesReserved, &point.InvitesConsumed, &point.InvitesReleased,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load registration trend"})
			return
		}
		point.Day = day.UTC().Format("2006-01-02")
		pointsByDay[point.Day] = point
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load registration trend"})
		return
	}
	trend := models.RegistrationTrend{Timezone: "UTC", Points: make([]models.RegistrationTrendPoint, 0, days)}
	for i := days - 1; i >= 0; i-- {
		day := today.AddDate(0, 0, -i).Format("2006-01-02")
		point := pointsByDay[day]
		point.Day = day
		trend.Points = append(trend.Points, point)
	}
	writeJSON(w, http.StatusOK, trend)
}

// GetMailTrend returns delivery-event aggregates from the schema-6
// observability boundary onward. OtherFailures contains failed attempts other
// than permanent recipient rejection; rejected remains independently visible.
func (h *Handler) GetMailTrend(w http.ResponseWriter, r *http.Request) {
	days, err := parseTrendDays(r, 30)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var availableFrom time.Time
	if err := h.db.QueryRow(r.Context(), `
		SELECT mail_stats_available_from FROM stats_observability_state WHERE singleton=TRUE
	`).Scan(&availableFrom); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, pgx.ErrNoRows) {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]string{"error": "mail statistics are not available"})
		return
	}
	today := utcDay(time.Now())
	start := today.AddDate(0, 0, -(days - 1))
	rows, err := h.db.Query(r.Context(), `
		SELECT day,enqueued,sent,failed_attempts,rejected,expired
		FROM mail_stats_daily
		WHERE day >= $1 AND day <= $2
		ORDER BY day
	`, start, today)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load mail trend"})
		return
	}
	defer rows.Close()
	pointsByDay := make(map[string]models.MailTrendPoint, days)
	for rows.Next() {
		var day time.Time
		var failedAttempts int64
		var point models.MailTrendPoint
		if err := rows.Scan(&day, &point.Enqueued, &point.Sent, &failedAttempts, &point.Rejected, &point.Expired); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load mail trend"})
			return
		}
		point.Day = day.UTC().Format("2006-01-02")
		point.OtherFailures = failedAttempts - point.Rejected
		pointsByDay[point.Day] = point
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load mail trend"})
		return
	}
	trend := models.MailTrend{
		Timezone: "UTC", AvailableFrom: availableFrom,
		Points: make([]models.MailTrendPoint, 0, days),
	}
	for i := days - 1; i >= 0; i-- {
		day := today.AddDate(0, 0, -i).Format("2006-01-02")
		point := pointsByDay[day]
		point.Day = day
		trend.Points = append(trend.Points, point)
	}
	writeJSON(w, http.StatusOK, trend)
}

// GetRecentLogins returns the most recent login entries.
func (h *Handler) GetRecentLogins(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit := 5
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 50 {
		limit = l
	}

	rows, err := h.db.Query(ctx, `
		SELECT COALESCE(actor_name, 'unknown'), COALESCE(result, 'unknown'), COALESCE(ip_address, '-'), created_at
		FROM audit_logs
		WHERE event IN ('user.login', 'user.login_failed')
		ORDER BY created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load recent logins"})
		return
	}
	defer rows.Close()

	var logins []map[string]string
	for rows.Next() {
		var name, result, ip string
		var createdAt time.Time
		if err := rows.Scan(&name, &result, &ip, &createdAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load recent logins"})
			return
		}
		logins = append(logins, map[string]string{
			"username": name,
			"result":   result,
			"ip":       ip,
			"time":     relativeTime(createdAt),
		})
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load recent logins"})
		return
	}

	if logins == nil {
		logins = []map[string]string{}
	}
	writeJSON(w, http.StatusOK, logins)
}

func (h *Handler) countActiveSessions(ctx context.Context) (int64, error) {
	return h.sessions.CountActiveSessions(ctx)
}

// Refresh rebuilds the bounded dashboard aggregates. Only one application
// instance performs the work at a time; other instances keep serving the last
// committed snapshot.
func (h *Handler) Refresh(ctx context.Context) error {
	if h == nil || h.db == nil || h.sessions == nil {
		return fmt.Errorf("statistics refresher is unavailable")
	}
	activeSessions, sessionCountErr := h.countActiveSessions(ctx)
	now := time.Now().UTC()
	today := utcDay(now)
	historyStart := today.AddDate(0, 0, -(statsHistoryDays - 1))

	tx, err := h.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting statistics refresh: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var acquired bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, statsRefreshLockID).Scan(&acquired); err != nil {
		return fmt.Errorf("locking statistics refresh: %w", err)
	}
	if !acquired {
		return nil
	}
	if sessionCountErr != nil {
		err := tx.QueryRow(ctx, `
			SELECT active_sessions FROM system_stats_snapshot WHERE singleton=TRUE
		`).Scan(&activeSessions)
		if errors.Is(err, pgx.ErrNoRows) {
			activeSessions = 0
		} else if err != nil {
			return fmt.Errorf("preserving active session statistics: %w", err)
		}
		slog.WarnContext(ctx, "active session statistics unavailable; preserving last snapshot", "error_class", "redis_unavailable")
	}

	if _, err := tx.Exec(ctx, `DELETE FROM login_stats_daily WHERE day < $1`, historyStart); err != nil {
		return fmt.Errorf("pruning login aggregates: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM registration_stats_daily WHERE day < $1`, historyStart); err != nil {
		return fmt.Errorf("pruning registration aggregates: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mail_stats_daily WHERE day < $1`, historyStart); err != nil {
		return fmt.Errorf("pruning mail aggregates: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mail_failure_stats_minute WHERE minute < $1`, now.Add(-48*time.Hour)); err != nil {
		return fmt.Errorf("pruning rolling mail failure aggregates: %w", err)
	}

	var userCount, appCount, loginCount7d, failedLogins7d int64
	var pendingRegistrations, completedRegistrations7d int64
	var registrationStarted30d, registrationCompleted30d int64
	var mailBacklog, mailFailures24h int64
	var smtpCircuitState string
	if err := tx.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM users),
			(SELECT COUNT(*) FROM oauth_clients),
			COALESCE((SELECT SUM(successful_logins) FROM login_stats_daily WHERE day >= $1), 0),
			COALESCE((SELECT SUM(failed_logins) FROM login_stats_daily WHERE day >= $1), 0),
			(SELECT COUNT(*) FROM self_registrations WHERE status='pending' AND expires_at>$2),
			COALESCE((SELECT SUM(registrations_completed) FROM registration_stats_daily WHERE day >= $1), 0),
			COALESCE((SELECT SUM(cohort_started) FROM registration_stats_daily WHERE day >= $3), 0),
			COALESCE((SELECT SUM(cohort_completed) FROM registration_stats_daily WHERE day >= $3), 0),
			(SELECT COUNT(*) FROM email_outbox WHERE status IN ('pending','failed','sending') AND expires_at>$2),
			COALESCE((
				SELECT SUM(failed_attempts) FROM mail_failure_stats_minute
				WHERE minute >= date_trunc('minute',$2::timestamptz - INTERVAL '24 hours')
				  AND minute <= date_trunc('minute',$2::timestamptz)
			), 0),
			(SELECT circuit_state FROM mail_runtime_state WHERE singleton=TRUE)
	`, today.AddDate(0, 0, -6), now, today.AddDate(0, 0, -29)).Scan(
		&userCount, &appCount, &loginCount7d, &failedLogins7d,
		&pendingRegistrations, &completedRegistrations7d,
		&registrationStarted30d, &registrationCompleted30d,
		&mailBacklog, &mailFailures24h, &smtpCircuitState,
	); err != nil {
		return fmt.Errorf("calculating statistics snapshot: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO system_stats_snapshot (
			singleton, user_count, app_count, active_sessions,
			login_count_7d, failed_logins_7d,
			pending_registrations, completed_registrations_7d,
			registration_started_30d, registration_completed_30d,
			mail_backlog, mail_failures_24h, smtp_circuit_state, refreshed_at
		) VALUES (TRUE, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (singleton) DO UPDATE SET
			user_count = EXCLUDED.user_count,
			app_count = EXCLUDED.app_count,
			active_sessions = EXCLUDED.active_sessions,
			login_count_7d = EXCLUDED.login_count_7d,
			failed_logins_7d = EXCLUDED.failed_logins_7d,
			pending_registrations = EXCLUDED.pending_registrations,
			completed_registrations_7d = EXCLUDED.completed_registrations_7d,
			registration_started_30d = EXCLUDED.registration_started_30d,
			registration_completed_30d = EXCLUDED.registration_completed_30d,
			mail_backlog = EXCLUDED.mail_backlog,
			mail_failures_24h = EXCLUDED.mail_failures_24h,
			smtp_circuit_state = EXCLUDED.smtp_circuit_state,
			refreshed_at = EXCLUDED.refreshed_at
	`, userCount, appCount, activeSessions, loginCount7d, failedLogins7d,
		pendingRegistrations, completedRegistrations7d,
		registrationStarted30d, registrationCompleted30d,
		mailBacklog, mailFailures24h, smtpCircuitState, now); err != nil {
		return fmt.Errorf("writing statistics snapshot: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing statistics refresh: %w", err)
	}
	return nil
}

// Run refreshes the aggregate snapshot until the server shuts down.
func (h *Handler) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := h.Refresh(ctx); err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "statistics refresh failed", "error_class", "dependency_unavailable")
			}
		}
	}
}

func utcDay(value time.Time) time.Time {
	value = value.UTC()
	return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, time.UTC)
}

func parseTrendDays(r *http.Request, defaultDays int) (int, error) {
	raw := r.URL.Query().Get("days")
	if raw == "" {
		return defaultDays, nil
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days < 7 || days > statsHistoryDays {
		return 0, fmt.Errorf("days must be an integer between 7 and %d", statsHistoryDays)
	}
	return days, nil
}

func relativeTime(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "刚刚"
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d 小时前", int(d.Hours()))
	default:
		return fmt.Sprintf("%d 天前", int(d.Hours()/24))
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
