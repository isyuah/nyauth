package server

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/notification"
	"github.com/nyasharp/nyauth/pkg/models"
)

func (s *Server) notifyUser(ctx context.Context, input notification.NotificationInput) {
	if s.notificationStore == nil || input.UserID == uuid.Nil {
		return
	}
	if err := s.notificationStore.CreateNotification(ctx, input); err != nil {
		slog.ErrorContext(ctx, "creating in-app notification failed", "notification_type", input.Type, "user_id", input.UserID, "error", err)
	}
}

func (s *Server) notifySecurityChange(ctx context.Context, userID uuid.UUID, typ notification.NotificationType, title, body, link string) {
	s.notifyUser(ctx, notification.NotificationInput{UserID: userID, Type: typ, Severity: notification.SeverityWarning, Title: title, BodyMarkdown: body, LinkURL: link, SourceType: "user", SourceID: userID.String()})
}

func (s *Server) notifyPublisherChange(ctx context.Context, client *models.OAuthClient, verified bool) {
	if client == nil || client.OwnerID == nil {
		return
	}
	ownerID, err := uuid.Parse(strings.TrimSpace(*client.OwnerID))
	if err != nil {
		return
	}
	name := escapeNotificationMarkdown(client.Name)
	typ, title, body := notification.TypePublisherRevoked, "应用发布者可信状态已撤销", "管理员已撤销应用 **"+name+"** 的发布者可信状态。后续授权页面会重新显示未验证提示。"
	if verified {
		typ, title, body = notification.TypePublisherVerified, "应用发布者已通过验证", "应用 **"+name+"** 的发布者身份已由管理员验证。"
	}
	s.notifyUser(ctx, notification.NotificationInput{UserID: ownerID, Type: typ, Severity: notification.SeverityInfo, Title: title, BodyMarkdown: body, LinkURL: "/dashboard/apps/" + client.ID, SourceType: "client", SourceID: client.ID, DedupeKey: string(typ) + ":" + client.ID + ":" + fmt.Sprint(client.IdentityRevision)})
}

func (s *Server) notifyDeviceAuthorized(ctx context.Context, rawUserID string, client *models.OAuthClient) {
	if client == nil {
		return
	}
	userID, err := uuid.Parse(strings.TrimSpace(rawUserID))
	if err != nil {
		return
	}
	name := escapeNotificationMarkdown(client.Name)
	s.notifyUser(ctx, notification.NotificationInput{
		UserID: userID, Type: notification.TypeDeviceAuthorized, Severity: notification.SeverityInfo,
		Title: "设备访问已授权", BodyMarkdown: "您已允许设备使用应用 **" + name + "** 访问账户。",
		LinkURL: "/profile/authorizations", SourceType: "client", SourceID: client.ID,
	})
}

func escapeNotificationMarkdown(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `*`, `\*`, `_`, `\_`, `[`, `\[`, `]`, `\]`, "`", "\\`")
	return replacer.Replace(value)
}
