package models

import (
	"time"

	"github.com/google/uuid"
)

// AuditLog represents an audit log entry.
type AuditLog struct {
	ID         uuid.UUID              `json:"id" db:"id"`
	Event      string                 `json:"event" db:"event"`
	ActorID    *uuid.UUID             `json:"actor_id,omitempty" db:"actor_id"`
	ActorName  *string                `json:"actor_name,omitempty" db:"actor_name"`
	TargetType *string                `json:"target_type,omitempty" db:"target_type"`
	TargetID   *string                `json:"target_id,omitempty" db:"target_id"`
	IPAddress  *string                `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent  *string                `json:"-" db:"user_agent"`
	Result     string                 `json:"result" db:"result"`
	RiskLevel  string                 `json:"risk_level" db:"risk_level"`
	Metadata   map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	CreatedAt  time.Time              `json:"created_at" db:"created_at"`
}

// Audit event types
const (
	AuditUserLogin        = "user.login"
	AuditUserLoginFailed  = "user.login_failed"
	AuditUserCreated      = "user.created"
	AuditUserDeleted      = "user.deleted"
	AuditUserSuspended    = "user.suspended"
	AuditUserActivated    = "user.activated"
	AuditClientCreated    = "client.created"
	AuditClientDeleted    = "client.deleted"
	AuditProviderCreated  = "provider.created"
	AuditProviderTested   = "provider.tested"
	AuditProviderDeleted  = "provider.deleted"
	AuditTokenIssued      = "token.issued"
	AuditTokenRevoked     = "token.revoked"
)

// DashboardStats holds system statistics.
type DashboardStats struct {
	UserCount       int64 `json:"user_count"`
	AppCount        int64 `json:"app_count"`
	LoginCount7d    int64 `json:"login_count_7d"`
	ActiveSessions  int64 `json:"active_sessions"`
	FailedLogins7d  int64 `json:"failed_logins_7d"`
}

// LoginTrend holds login trend data.
type LoginTrend struct {
	Labels []string `json:"labels"`
	Values []int64  `json:"values"`
}

// RecentLogin holds a recent login entry for the dashboard.
type RecentLogin struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Result   string `json:"result"`
	IP       string `json:"ip"`
	Time     string `json:"time"`
}
