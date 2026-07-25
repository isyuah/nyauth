package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/pkg/models"
)

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
	_, err := s.db.Exec(ctx, `
		INSERT INTO audit_logs (id, event, actor_id, actor_name, target_type, target_id, ip_address, user_agent, result, risk_level, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, entry.ID, entry.Event, entry.ActorID, entry.ActorName, entry.TargetType, entry.TargetID,
		entry.IPAddress, entry.UserAgent, entry.Result, entry.RiskLevel, entry.Metadata)
	return err
}

// List retrieves audit logs with pagination and optional filters.
func (s *Store) List(ctx context.Context, page, pageSize int, event string) (*models.PaginatedResponse[models.AuditLog], error) {
	p := models.NewPagination(page, pageSize)

	countQuery := `SELECT COUNT(*) FROM audit_logs`
	args := []interface{}{}
	if event != "" {
		countQuery += ` WHERE event = $1`
		args = append(args, event)
	}

	var total int64
	if err := s.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("counting audit logs: %w", err)
	}

	query := `SELECT id, event, actor_id, actor_name, target_type, target_id, ip_address, user_agent, result, risk_level, metadata, created_at FROM audit_logs`
	listArgs := []interface{}{p.PageSize, p.Offset()}
	if event != "" {
		query += ` WHERE event = $3`
		listArgs = append(listArgs, event)
	}
	query += ` ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	rows, err := s.db.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, fmt.Errorf("listing audit logs: %w", err)
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		if err := rows.Scan(&l.ID, &l.Event, &l.ActorID, &l.ActorName, &l.TargetType, &l.TargetID,
			&l.IPAddress, &l.UserAgent, &l.Result, &l.RiskLevel, &l.Metadata, &l.CreatedAt); err != nil {
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
