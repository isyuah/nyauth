package oauthops

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/pkg/models"
)

type Store struct{ db *pgxpool.Pool }

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

func (store *Store) Record(ctx context.Context, event Event) error {
	if err := event.Normalize(); err != nil {
		return err
	}
	tx, err := store.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting OAuth operation record: %w", err)
	}
	defer tx.Rollback(ctx)
	success, failure := int64(0), int64(0)
	var lastSuccess, lastFailure *time.Time
	if event.Outcome == OutcomeSuccess {
		success, lastSuccess = 1, &event.OccurredAt
	} else {
		failure, lastFailure = 1, &event.OccurredAt
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO oauth_client_stats_daily (
			client_id,day,flow,stage,success_count,failure_count,last_success_at,last_failure_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (client_id,day,flow,stage) DO UPDATE SET
			success_count=oauth_client_stats_daily.success_count+EXCLUDED.success_count,
			failure_count=oauth_client_stats_daily.failure_count+EXCLUDED.failure_count,
			last_success_at=GREATEST(oauth_client_stats_daily.last_success_at,EXCLUDED.last_success_at),
			last_failure_at=GREATEST(oauth_client_stats_daily.last_failure_at,EXCLUDED.last_failure_at)
	`, event.ClientID, event.OccurredAt.Format("2006-01-02"), event.Flow, event.Stage, success, failure, lastSuccess, lastFailure); err != nil {
		return fmt.Errorf("aggregating OAuth client operation: %w", err)
	}
	if event.Outcome == OutcomeFailure {
		var requestID, redirectURI any
		if event.RequestID != "" {
			requestID = event.RequestID
		}
		if event.RedirectURI != "" {
			redirectURI = event.RedirectURI
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_client_diagnostics (client_id,occurred_at,request_id,flow,stage,reason,redirect_uri,scopes)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		`, event.ClientID, event.OccurredAt, requestID, event.Flow, event.Stage, event.Reason, redirectURI, event.Scopes); err != nil {
			return fmt.Errorf("recording OAuth client diagnostic: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing OAuth operation record: %w", err)
	}
	return nil
}

type Totals struct {
	Success     int64    `json:"success"`
	Failure     int64    `json:"failure"`
	Total       int64    `json:"total"`
	SuccessRate *float64 `json:"success_rate"`
}

type TrendPoint struct {
	Day     string `json:"day"`
	Success int64  `json:"success"`
	Failure int64  `json:"failure"`
}

type Breakdown struct {
	Flow    Flow  `json:"flow"`
	Stage   Stage `json:"stage"`
	Success int64 `json:"success"`
	Failure int64 `json:"failure"`
}

type Insights struct {
	ClientID             string       `json:"client_id"`
	Days                 int          `json:"days"`
	Timezone             string       `json:"timezone"`
	Totals               Totals       `json:"totals"`
	ActiveAuthorizations int64        `json:"active_authorizations"`
	LastSuccessAt        *time.Time   `json:"last_success_at,omitempty"`
	LastFailureAt        *time.Time   `json:"last_failure_at,omitempty"`
	Trend                []TrendPoint `json:"trend"`
	Breakdown            []Breakdown  `json:"breakdown"`
}

func (store *Store) GetInsights(ctx context.Context, clientID string, days int) (*Insights, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" || days < 1 || days > 90 {
		return nil, errors.New("invalid OAuth client insights request")
	}
	var exists bool
	if err := store.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oauth_clients WHERE id=$1)`, clientID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("checking OAuth client: %w", err)
	}
	if !exists {
		return nil, pgx.ErrNoRows
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	start := today.AddDate(0, 0, -(days - 1))
	result := &Insights{ClientID: clientID, Days: days, Timezone: "UTC", Trend: make([]TrendPoint, 0, days), Breakdown: []Breakdown{}}
	if err := store.db.QueryRow(ctx, `
		SELECT COALESCE(SUM(success_count),0),COALESCE(SUM(failure_count),0),MAX(last_success_at),MAX(last_failure_at)
		FROM oauth_client_stats_daily WHERE client_id=$1 AND day >= $2 AND day <= $3
	`, clientID, start, today).Scan(&result.Totals.Success, &result.Totals.Failure, &result.LastSuccessAt, &result.LastFailureAt); err != nil {
		return nil, fmt.Errorf("reading OAuth client totals: %w", err)
	}
	result.Totals.Total = result.Totals.Success + result.Totals.Failure
	if result.Totals.Total > 0 {
		rate := math.Round((float64(result.Totals.Success)/float64(result.Totals.Total))*10000) / 100
		result.Totals.SuccessRate = &rate
	}
	if err := store.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM oauth_authorizations a
		JOIN oauth_clients c ON c.id=a.client_id
		WHERE a.client_id=$1 AND a.revoked_at IS NULL AND a.client_authorization_revision=c.authorization_revision
	`, clientID).Scan(&result.ActiveAuthorizations); err != nil {
		return nil, fmt.Errorf("counting active OAuth authorizations: %w", err)
	}
	rows, err := store.db.Query(ctx, `
		SELECT day,SUM(success_count),SUM(failure_count)
		FROM oauth_client_stats_daily WHERE client_id=$1 AND day >= $2 AND day <= $3
		GROUP BY day ORDER BY day
	`, clientID, start, today)
	if err != nil {
		return nil, fmt.Errorf("reading OAuth client trend: %w", err)
	}
	points := make(map[string]TrendPoint, days)
	for rows.Next() {
		var day time.Time
		var point TrendPoint
		if err := rows.Scan(&day, &point.Success, &point.Failure); err != nil {
			rows.Close()
			return nil, err
		}
		point.Day = day.UTC().Format("2006-01-02")
		points[point.Day] = point
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for offset := days - 1; offset >= 0; offset-- {
		day := today.AddDate(0, 0, -offset).Format("2006-01-02")
		point := points[day]
		point.Day = day
		result.Trend = append(result.Trend, point)
	}
	rows, err = store.db.Query(ctx, `
		SELECT flow,stage,SUM(success_count),SUM(failure_count)
		FROM oauth_client_stats_daily WHERE client_id=$1 AND day >= $2 AND day <= $3
		GROUP BY flow,stage ORDER BY flow,stage
	`, clientID, start, today)
	if err != nil {
		return nil, fmt.Errorf("reading OAuth client breakdown: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item Breakdown
		if err := rows.Scan(&item.Flow, &item.Stage, &item.Success, &item.Failure); err != nil {
			return nil, err
		}
		result.Breakdown = append(result.Breakdown, item)
	}
	return result, rows.Err()
}

type Diagnostic struct {
	ID          uuid.UUID `json:"id"`
	OccurredAt  time.Time `json:"occurred_at"`
	RequestID   *string   `json:"request_id,omitempty"`
	Flow        Flow      `json:"flow"`
	Stage       Stage     `json:"stage"`
	Reason      Reason    `json:"reason"`
	RedirectURI *string   `json:"redirect_uri,omitempty"`
	Scopes      []string  `json:"scopes"`
}

type DiagnosticFilter struct {
	ClientID string
	Flow     string
	Stage    string
	Reason   string
	Page     int
	PageSize int
}

func (store *Store) ListDiagnostics(ctx context.Context, filter DiagnosticFilter) (*models.PaginatedResponse[Diagnostic], error) {
	filter.ClientID = strings.TrimSpace(filter.ClientID)
	if filter.ClientID == "" {
		return nil, errors.New("client ID is required")
	}
	if filter.Flow != "" && !ValidFlow(filter.Flow) {
		return nil, errors.New("invalid flow filter")
	}
	if filter.Stage != "" && !ValidStage(filter.Stage) {
		return nil, errors.New("invalid stage filter")
	}
	if filter.Reason != "" && !ValidReason(filter.Reason) {
		return nil, errors.New("invalid reason filter")
	}
	pagination := models.NewPagination(filter.Page, filter.PageSize)
	where := []string{"client_id=$1"}
	args := []any{filter.ClientID}
	add := func(column, value string) {
		if value == "" {
			return
		}
		args = append(args, value)
		where = append(where, fmt.Sprintf("%s=$%d", column, len(args)))
	}
	add("flow", filter.Flow)
	add("stage", filter.Stage)
	add("reason", filter.Reason)
	clause := strings.Join(where, " AND ")
	var total int64
	if err := store.db.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_client_diagnostics WHERE `+clause, args...).Scan(&total); err != nil {
		return nil, err
	}
	args = append(args, pagination.PageSize, pagination.Offset())
	rows, err := store.db.Query(ctx, `
		SELECT id,occurred_at,request_id,flow,stage,reason,redirect_uri,scopes
		FROM oauth_client_diagnostics WHERE `+clause+`
		ORDER BY occurred_at DESC,id DESC LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("listing OAuth diagnostics: %w", err)
	}
	defer rows.Close()
	items := make([]Diagnostic, 0, pagination.PageSize)
	for rows.Next() {
		var item Diagnostic
		if err := rows.Scan(&item.ID, &item.OccurredAt, &item.RequestID, &item.Flow, &item.Stage, &item.Reason, &item.RedirectURI, &item.Scopes); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	totalPages := (int(total) + pagination.PageSize - 1) / pagination.PageSize
	return &models.PaginatedResponse[Diagnostic]{Items: items, Total: total, Page: pagination.Page, PageSize: pagination.PageSize, TotalPages: totalPages}, nil
}

func (store *Store) Cleanup(ctx context.Context, now time.Time) (diagnostics, daily int64, err error) {
	result, err := store.db.Exec(ctx, `DELETE FROM oauth_client_diagnostics WHERE occurred_at < $1`, now.UTC().AddDate(0, 0, -90))
	if err != nil {
		return 0, 0, fmt.Errorf("cleaning OAuth diagnostics: %w", err)
	}
	diagnostics = result.RowsAffected()
	result, err = store.db.Exec(ctx, `DELETE FROM oauth_client_stats_daily WHERE day < $1`, now.UTC().AddDate(0, 0, -400))
	if err != nil {
		return diagnostics, 0, fmt.Errorf("cleaning OAuth daily statistics: %w", err)
	}
	return diagnostics, result.RowsAffected(), nil
}
