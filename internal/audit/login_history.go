package audit

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

func (s *Store) ListLoginHistory(
	ctx context.Context,
	userID uuid.UUID,
	page, pageSize int,
) (*models.PaginatedResponse[models.LoginHistoryEntry], error) {
	pagination := models.NewPagination(page, pageSize)
	events := []string{models.AuditUserLogin, models.AuditUserLoginFailed, models.AuditMFAChallengeFailed}
	var total int64
	if err := s.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE actor_id=$1 AND event=ANY($2::text[])
		  AND (event<>$3 OR details->>'purpose'='login')
		  AND (event<>$4 OR COALESCE(details->>'purpose','login') NOT LIKE '%reauthentication%')
	`, userID, events, models.AuditMFAChallengeFailed, models.AuditUserLoginFailed).Scan(&total); err != nil {
		return nil, fmt.Errorf("counting login history: %w", err)
	}
	rows, err := s.db.Query(ctx, `
		SELECT id,event,ip_address,user_agent,result,details,created_at
		FROM audit_logs
		WHERE actor_id=$1 AND event=ANY($2::text[])
		  AND (event<>$3 OR details->>'purpose'='login')
		  AND (event<>$4 OR COALESCE(details->>'purpose','login') NOT LIKE '%reauthentication%')
		ORDER BY created_at DESC,id DESC
		LIMIT $5 OFFSET $6
	`, userID, events, models.AuditMFAChallengeFailed, models.AuditUserLoginFailed, pagination.PageSize, pagination.Offset())
	if err != nil {
		return nil, fmt.Errorf("listing login history: %w", err)
	}
	defer rows.Close()
	items := make([]models.LoginHistoryEntry, 0, pagination.PageSize)
	for rows.Next() {
		var item models.LoginHistoryEntry
		var event string
		var ipAddress, userAgent *string
		var details map[string]any
		if err := rows.Scan(&item.ID, &event, &ipAddress, &userAgent, &item.Result, &details, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning login history: %w", err)
		}
		item.AuthenticationMethod = loginHistoryDetail(details, "authentication_method")
		if item.AuthenticationMethod == "" {
			item.AuthenticationMethod = loginHistoryDetail(details, "primary_method")
		}
		if item.AuthenticationMethod == "" {
			item.AuthenticationMethod = "unknown"
		}
		item.SecondFactor = loginHistoryDetail(details, "second_factor")
		if item.SecondFactor == "" && event == models.AuditMFAChallengeFailed {
			item.SecondFactor = loginHistoryDetail(details, "mfa_method")
		}
		item.Provider = loginHistoryDetail(details, "provider")
		if ipAddress != nil {
			item.IPAddress = *ipAddress
		}
		if userAgent != nil {
			item.UserAgent = *userAgent
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating login history: %w", err)
	}
	totalPages := int(total) / pagination.PageSize
	if int(total)%pagination.PageSize != 0 {
		totalPages++
	}
	return &models.PaginatedResponse[models.LoginHistoryEntry]{
		Items: items, Total: total, Page: pagination.Page,
		PageSize: pagination.PageSize, TotalPages: totalPages,
	}, nil
}

func loginHistoryDetail(details map[string]any, key string) string {
	value, _ := details[key].(string)
	return value
}
