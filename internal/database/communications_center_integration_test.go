package database_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/notification"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestCommunicationsCenterLifecycleReadStateAndDedupe(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("migrate schema: %v", err)
	}
	ctx := context.Background()
	adminID, userID := uuid.New(), uuid.New()
	if _, err := schema.pool.Exec(ctx, `INSERT INTO users(id,username,status,role,creation_source) VALUES($1,'announcement-admin','active','admin','admin'),($2,'announcement-user','active','user','admin')`, adminID, userID); err != nil {
		t.Fatalf("insert users: %v", err)
	}
	store := notification.NewStore(schema.pool)
	mutation := func(event string) audit.MutationAudit {
		return audit.MutationAudit{Event: event, ActorID: adminID, ActorName: "announcement-admin", Result: "success", RiskLevel: "medium"}
	}
	draft, err := store.CreateAnnouncement(ctx, notification.AnnouncementInput{Severity: notification.SeverityWarning, Audience: notification.AudienceAuthenticated, Title: "Maintenance", Summary: "Planned work", BodyMarkdown: "Review **your sessions**.", LinkURL: "/profile/sessions", Pinned: true}, adminID, mutation(models.AuditAnnouncementCreated))
	if err != nil {
		t.Fatalf("create announcement: %v", err)
	}
	if _, err := store.UpdateAnnouncement(ctx, draft.ID, notification.AnnouncementInput{Title: "stale", BodyMarkdown: "stale"}, draft.Revision+1, adminID, mutation(models.AuditAnnouncementUpdated)); !errors.Is(err, notification.ErrRevisionConflict) {
		t.Fatalf("stale update error = %v", err)
	}
	published, err := store.PublishAnnouncement(ctx, draft.ID, draft.Revision, adminID, mutation(models.AuditAnnouncementPublished))
	if err != nil {
		t.Fatalf("publish announcement: %v", err)
	}
	if _, err := store.PublishAnnouncement(ctx, published.ID, published.Revision, adminID, mutation(models.AuditAnnouncementPublished)); !errors.Is(err, notification.ErrInvalidTransition) {
		t.Fatalf("republish error = %v", err)
	}
	page, err := store.ListForUser(ctx, userID, false, notification.ListOptions{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("list announcements: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].Read || page.Items[0].BodyHTML != "" {
		t.Fatalf("unexpected announcement page: %#v", page.Items)
	}
	if count, err := store.UnreadAnnouncementCount(ctx, userID, false); err != nil || count != 1 {
		t.Fatalf("unread announcements = %d, %v", count, err)
	}
	if err := store.MarkAnnouncementRead(ctx, published.ID, userID, false); err != nil {
		t.Fatalf("mark announcement read: %v", err)
	}
	if count, err := store.UnreadAnnouncementCount(ctx, userID, false); err != nil || count != 0 {
		t.Fatalf("read announcement count = %d, %v", count, err)
	}
	updated, err := store.UpdateAnnouncement(ctx, published.ID, notification.AnnouncementInput{Severity: notification.SeverityWarning, Audience: notification.AudienceAuthenticated, Title: "Maintenance updated", Summary: "New details", BodyMarkdown: "Updated **details**.", LinkURL: "/profile/sessions", Pinned: true}, published.Revision, adminID, mutation(models.AuditAnnouncementUpdated))
	if err != nil {
		t.Fatalf("update published announcement: %v", err)
	}
	if count, err := store.UnreadAnnouncementCount(ctx, userID, false); err != nil || count != 1 {
		t.Fatalf("updated announcement unread count = %d, %v", count, err)
	}
	publicItem, err := store.GetForUser(ctx, updated.ID, userID, false)
	if err != nil {
		t.Fatalf("get public announcement: %v", err)
	}
	if publicItem.BodyMarkdown != "" || publicItem.CreatedBy != nil || publicItem.UpdatedBy != nil {
		t.Fatalf("public announcement leaked editor fields: %#v", publicItem)
	}
	if _, err := store.UpdateAnnouncement(ctx, updated.ID, notification.AnnouncementInput{Title: "", BodyMarkdown: ""}, updated.Revision, adminID, mutation(models.AuditAnnouncementUpdated)); !errors.Is(err, notification.ErrInvalidInput) {
		t.Fatalf("published announcement accepted empty content: %v", err)
	}
	if _, err := store.PublishAnnouncement(ctx, uuid.New(), 1, adminID, mutation(models.AuditAnnouncementPublished)); !errors.Is(err, notification.ErrNotFound) {
		t.Fatalf("missing announcement publish error = %v", err)
	}

	input := notification.NotificationInput{UserID: userID, Type: notification.TypePasswordChanged, Severity: notification.SeverityWarning, Title: "Password changed", BodyMarkdown: "Review your **security settings**.", LinkURL: "/profile/security", SourceType: "user", SourceID: userID.String(), DedupeKey: "password-change:test"}
	if err := store.CreateNotification(ctx, input); err != nil {
		t.Fatalf("create notification: %v", err)
	}
	if err := store.CreateNotification(ctx, input); err != nil {
		t.Fatalf("dedupe notification: %v", err)
	}
	messagePage, err := store.ListMessageCenter(ctx, userID, false, notification.MessageCenterOptions{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("list combined message center: %v", err)
	}
	if messagePage.Total != 2 || len(messagePage.Items) != 2 || messagePage.Items[0].Kind != notification.MessageKindNotification || messagePage.Items[1].Kind != notification.MessageKindAnnouncement {
		t.Fatalf("unexpected combined message page: %#v", messagePage)
	}
	filteredMessages, err := store.ListMessageCenter(ctx, userID, false, notification.MessageCenterOptions{
		Kind: notification.MessageKindNotification, Read: notification.MessageUnreadOnly,
		Severity: notification.SeverityWarning, Query: "security settings",
	})
	if err != nil || filteredMessages.Total != 1 || len(filteredMessages.Items) != 1 || filteredMessages.Items[0].BodyHTML == "" {
		t.Fatalf("filtered notification messages = %#v, %v", filteredMessages, err)
	}
	windowStart, windowEnd := time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Minute)
	announcementMessages, err := store.ListMessageCenter(ctx, userID, false, notification.MessageCenterOptions{
		Kind: notification.MessageKindAnnouncement, Query: "Maintenance updated", From: &windowStart, To: &windowEnd,
	})
	if err != nil || announcementMessages.Total != 1 || len(announcementMessages.Items) != 1 || announcementMessages.Items[0].Summary != "New details" {
		t.Fatalf("filtered announcement messages = %#v, %v", announcementMessages, err)
	}
	if _, err := store.ListMessageCenter(ctx, userID, false, notification.MessageCenterOptions{Kind: "unknown"}); !errors.Is(err, notification.ErrInvalidInput) {
		t.Fatalf("unknown message kind error = %v", err)
	}
	notifications, err := store.ListNotifications(ctx, userID, false, 1, 20)
	if err != nil {
		t.Fatalf("list notifications: %v", err)
	}
	if notifications.Total != 1 || len(notifications.Items) != 1 || notifications.Items[0].BodyHTML == "" {
		t.Fatalf("unexpected notification page: %#v", notifications)
	}
	if count, err := store.UnreadCount(ctx, userID); err != nil || count != 1 {
		t.Fatalf("unread notifications = %d, %v", count, err)
	}
	if err := store.MarkAllMessagesRead(ctx, userID, false, notification.MessageKindNotification); err != nil {
		t.Fatalf("mark notification messages read: %v", err)
	}
	if count, _ := store.UnreadCount(ctx, userID); count != 0 {
		t.Fatalf("unread notifications after category read = %d", count)
	}
	if count, _ := store.UnreadAnnouncementCount(ctx, userID, false); count != 1 {
		t.Fatalf("announcement was unexpectedly marked read = %d", count)
	}
	if err := store.MarkAllMessagesRead(ctx, userID, false, notification.MessageKindAll); err != nil {
		t.Fatalf("mark all messages read: %v", err)
	}
	readMessages, err := store.ListMessageCenter(ctx, userID, false, notification.MessageCenterOptions{Read: notification.MessageReadOnly})
	if err != nil || readMessages.Total != 2 {
		t.Fatalf("read message page = %#v, %v", readMessages, err)
	}
	if err := store.MarkAllNotificationsRead(ctx, userID); err != nil {
		t.Fatalf("mark all read: %v", err)
	}
	if count, _ := store.UnreadCount(ctx, userID); count != 0 {
		t.Fatalf("unread after mark all = %d", count)
	}

	adminOnly, err := store.CreateAnnouncement(ctx, notification.AnnouncementInput{Severity: notification.SeverityInfo, Audience: notification.AudienceAdmins, Title: "Admin notice", BodyMarkdown: "Administrators only."}, adminID, mutation(models.AuditAnnouncementCreated))
	if err != nil {
		t.Fatalf("create admin announcement: %v", err)
	}
	adminOnly, err = store.PublishAnnouncement(ctx, adminOnly.ID, adminOnly.Revision, adminID, mutation(models.AuditAnnouncementPublished))
	if err != nil {
		t.Fatalf("publish admin announcement: %v", err)
	}
	if err := store.MarkAnnouncementRead(ctx, adminOnly.ID, userID, false); !errors.Is(err, notification.ErrNotFound) {
		t.Fatalf("non-admin read of admin announcement error = %v", err)
	}
	if err := store.MarkAnnouncementRead(ctx, adminOnly.ID, adminID, true); err != nil {
		t.Fatalf("admin read of admin announcement: %v", err)
	}
}
