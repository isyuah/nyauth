package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/pkg/models"
)

type ListFilter struct {
	Event       string
	Result      string
	RiskLevel   string
	Actor       string
	Target      string
	IPAddress   string
	CreatedFrom *time.Time
	CreatedTo   *time.Time
}

// Store handles audit log persistence.
type Store struct {
	db *pgxpool.Pool
}

// NewStore creates a new audit store.
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// Record inserts a new audit log entry.
func (s *Store) Record(ctx context.Context, entry *models.AuditLog) error {
	if entry == nil {
		return fmt.Errorf("audit log entry is required")
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	} else {
		entry.CreatedAt = entry.CreatedAt.UTC()
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO audit_logs (id, event, actor_id, actor_name, target_type, target_id, ip_address, user_agent, result, risk_level, details, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, entry.ID, entry.Event, entry.ActorID, entry.ActorName, entry.TargetType, entry.TargetID,
		entry.IPAddress, entry.UserAgent, entry.Result, entry.RiskLevel, entry.Details, entry.CreatedAt)
	if err != nil {
		return fmt.Errorf("inserting audit log: %w", err)
	}
	return nil
}

// List retrieves audit logs with pagination and optional filters.
func (s *Store) List(ctx context.Context, page, pageSize int, filter ListFilter) (*models.PaginatedResponse[models.AuditLog], error) {
	p := models.NewPagination(page, pageSize)
	where, filterArgs := buildListFilter(filter)
	countQuery := `SELECT COUNT(*) FROM audit_logs` + where

	var total int64
	if err := s.db.QueryRow(ctx, countQuery, filterArgs...).Scan(&total); err != nil {
		return nil, fmt.Errorf("counting audit logs: %w", err)
	}

	query := `SELECT id, event, actor_id, actor_name, target_type, target_id, ip_address, user_agent, result, risk_level, details, created_at FROM audit_logs` + where
	listArgs := append([]any{}, filterArgs...)
	limitPlaceholder := len(listArgs) + 1
	offsetPlaceholder := len(listArgs) + 2
	listArgs = append(listArgs, p.PageSize, p.Offset())
	query += fmt.Sprintf(` ORDER BY created_at DESC,id DESC LIMIT $%d OFFSET $%d`, limitPlaceholder, offsetPlaceholder)

	rows, err := s.db.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, fmt.Errorf("listing audit logs: %w", err)
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		if err := rows.Scan(&l.ID, &l.Event, &l.ActorID, &l.ActorName, &l.TargetType, &l.TargetID,
			&l.IPAddress, &l.UserAgent, &l.Result, &l.RiskLevel, &l.Details, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning audit log: %w", err)
		}
		logs = append(logs, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating audit logs: %w", err)
	}

	totalPages := int(total) / p.PageSize
	if int(total)%p.PageSize > 0 {
		totalPages++
	}

	return &models.PaginatedResponse[models.AuditLog]{
		Items: logs, Total: total, Page: p.Page, PageSize: p.PageSize, TotalPages: totalPages,
	}, nil
}

// Stream visits a bounded, chronological audit export without buffering the
// complete result in memory. Callers must apply an explicit time window in the
// filter before exposing this method over HTTP.
func (s *Store) Stream(ctx context.Context, filter ListFilter, limit int, visit func(models.AuditLog) error) (int, error) {
	if limit < 1 || limit > 50_000 {
		return 0, fmt.Errorf("audit export limit must be between 1 and 50000")
	}
	if visit == nil {
		return 0, fmt.Errorf("audit export visitor is required")
	}
	where, args := buildListFilter(filter)
	args = append(args, limit)
	query := `SELECT id, event, actor_id, actor_name, target_type, target_id, ip_address, user_agent, result, risk_level, details, created_at FROM audit_logs` +
		where + fmt.Sprintf(` ORDER BY created_at ASC,id ASC LIMIT $%d`, len(args))
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("querying audit export: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var entry models.AuditLog
		if err := rows.Scan(&entry.ID, &entry.Event, &entry.ActorID, &entry.ActorName, &entry.TargetType, &entry.TargetID,
			&entry.IPAddress, &entry.UserAgent, &entry.Result, &entry.RiskLevel, &entry.Details, &entry.CreatedAt); err != nil {
			return count, fmt.Errorf("scanning audit export: %w", err)
		}
		if err := visit(entry); err != nil {
			return count, err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return count, fmt.Errorf("iterating audit export: %w", err)
	}
	return count, nil
}

func buildListFilter(filter ListFilter) (string, []any) {
	conditions := make([]string, 0, 8)
	args := make([]any, 0, 8)
	add := func(format string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(format, len(args)))
	}
	addRepeated := func(format string, value any) {
		args = append(args, value)
		index := len(args)
		conditions = append(conditions, fmt.Sprintf(format, index, index))
	}
	if value := strings.TrimSpace(filter.Event); value != "" {
		add("event = $%d", value)
	}
	if value := strings.TrimSpace(filter.Result); value != "" {
		add("result = $%d", value)
	}
	if value := strings.TrimSpace(filter.RiskLevel); value != "" {
		add("risk_level = $%d", value)
	}
	if value := strings.TrimSpace(filter.Actor); value != "" {
		addRepeated("(actor_name ILIKE '%%' || $%d || '%%' OR actor_id::text = $%d)", value)
	}
	if value := strings.TrimSpace(filter.Target); value != "" {
		addRepeated("(target_id ILIKE '%%' || $%d || '%%' OR target_type ILIKE '%%' || $%d || '%%')", value)
	}
	if value := strings.TrimSpace(filter.IPAddress); value != "" {
		add("ip_address = $%d", value)
	}
	if filter.CreatedFrom != nil {
		add("created_at >= $%d", *filter.CreatedFrom)
	}
	if filter.CreatedTo != nil {
		add("created_at <= $%d", *filter.CreatedTo)
	}
	if len(conditions) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}

// CountEvents counts audit events matching a filter.
func (s *Store) CountEvents(ctx context.Context, event string, since *time.Time) (int64, error) {
	var count int64
	query := `SELECT COUNT(*) FROM audit_logs WHERE event = $1`
	args := []any{event}
	if since != nil {
		query += ` AND created_at >= $2`
		args = append(args, *since)
	}
	if err := s.db.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
