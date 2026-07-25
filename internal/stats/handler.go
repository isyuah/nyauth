package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

// Handler handles stats API endpoints.
type Handler struct {
	db  *pgxpool.Pool
	rdb *redis.Client
}

// NewHandler creates a new stats handler.
func NewHandler(db *pgxpool.Pool, rdb *redis.Client) *Handler {
	return &Handler{db: db, rdb: rdb}
}

// GetStats returns system-wide statistics.
func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stats := models.DashboardStats{}

	// User count
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&stats.UserCount)

	// App count
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_clients`).Scan(&stats.AppCount)

	// Login count (7 days)
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs WHERE event = 'user.login' AND created_at >= NOW() - INTERVAL '7 days'`).Scan(&stats.LoginCount7d)

	// Active sessions (count distinct tokens in Redis)
	stats.ActiveSessions = h.countActiveSessions(ctx)

	// Failed logins (7 days)
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs WHERE event = 'user.login_failed' AND created_at >= NOW() - INTERVAL '7 days'`).Scan(&stats.FailedLogins7d)

	writeJSON(w, http.StatusOK, stats)
}

// GetLoginTrend returns login counts per day for the last N days.
func (h *Handler) GetLoginTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	days := 7
	if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d > 0 && d <= 90 {
		days = d
	}

	trend := models.LoginTrend{}
	for i := days - 1; i >= 0; i-- {
		day := time.Now().AddDate(0, 0, -i)
		label := day.Format("01-02")
		trend.Labels = append(trend.Labels, label)

		var count int64
		_ = h.db.QueryRow(ctx, `
			SELECT COUNT(*) FROM audit_logs
			WHERE event = 'user.login'
			AND created_at >= $1::date AND created_at < ($1::date + INTERVAL '1 day')
		`, day.Format("2006-01-02")).Scan(&count)
		trend.Values = append(trend.Values, count)
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
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()

	var logins []map[string]string
	for rows.Next() {
		var name, result, ip string
		var createdAt time.Time
		if err := rows.Scan(&name, &result, &ip, &createdAt); err != nil {
			continue
		}
		logins = append(logins, map[string]string{
			"username": name,
			"result":   result,
			"ip":       ip,
			"time":     relativeTime(createdAt),
		})
	}

	if logins == nil {
		logins = []map[string]string{}
	}
	writeJSON(w, http.StatusOK, logins)
}

func (h *Handler) countActiveSessions(ctx context.Context) int64 {
	// Count keys matching token prefix pattern
	var count int64
	iter := h.rdb.Scan(ctx, 0, "nyauth:token:*", 1000).Iterator()
	for iter.Next(ctx) {
		count++
	}
	return count
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
