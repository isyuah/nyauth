package stats

import (
	"context"
	"encoding/json"
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
	if err := h.db.QueryRow(ctx, `
		SELECT user_count, app_count, active_sessions, login_count_7d, failed_logins_7d
		FROM system_stats_snapshot
		WHERE singleton = TRUE
	`).Scan(&stats.UserCount, &stats.AppCount, &stats.ActiveSessions, &stats.LoginCount7d, &stats.FailedLogins7d); err != nil {
		status := http.StatusInternalServerError
		if err == pgx.ErrNoRows {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]string{"error": "statistics are not available"})
		return
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
	activeSessions, err := h.countActiveSessions(ctx)
	if err != nil {
		return fmt.Errorf("counting active sessions: %w", err)
	}
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

	if _, err := tx.Exec(ctx, `DELETE FROM login_stats_daily WHERE day < $1`, historyStart); err != nil {
		return fmt.Errorf("pruning login aggregates: %w", err)
	}

	var userCount, appCount, loginCount7d, failedLogins7d int64
	if err := tx.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM users),
			(SELECT COUNT(*) FROM oauth_clients),
			COALESCE((SELECT SUM(successful_logins) FROM login_stats_daily WHERE day >= $1), 0),
			COALESCE((SELECT SUM(failed_logins) FROM login_stats_daily WHERE day >= $1), 0)
	`, today.AddDate(0, 0, -6)).Scan(&userCount, &appCount, &loginCount7d, &failedLogins7d); err != nil {
		return fmt.Errorf("calculating statistics snapshot: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO system_stats_snapshot (
			singleton, user_count, app_count, active_sessions,
			login_count_7d, failed_logins_7d, refreshed_at
		) VALUES (TRUE, $1, $2, $3, $4, $5, $6)
		ON CONFLICT (singleton) DO UPDATE SET
			user_count = EXCLUDED.user_count,
			app_count = EXCLUDED.app_count,
			active_sessions = EXCLUDED.active_sessions,
			login_count_7d = EXCLUDED.login_count_7d,
			failed_logins_7d = EXCLUDED.failed_logins_7d,
			refreshed_at = EXCLUDED.refreshed_at
	`, userCount, appCount, activeSessions, loginCount7d, failedLogins7d, now); err != nil {
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
