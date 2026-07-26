package database_test

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/registration"
	"github.com/nyasharp/nyauth/internal/session"
	dashboardstats "github.com/nyasharp/nyauth/internal/stats"
	migrationfiles "github.com/nyasharp/nyauth/migrations"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

func TestRegistrationStatsMigrationBackfillsLifecycleHistory(t *testing.T) {
	schema := newMigratedRegistrationSchema(t)
	source, err := iofs.New(migrationfiles.Files, ".")
	if err != nil {
		t.Fatalf("open migration source: %v", err)
	}
	runner, err := migrate.NewWithSourceInstance("iofs", source, schema.migrationDSN)
	if err != nil {
		_ = source.Close()
		t.Fatalf("create migration runner: %v", err)
	}
	t.Cleanup(func() { _, _ = runner.Close() })
	if err := runner.Steps(-1); err != nil {
		t.Fatalf("migrate observability down: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	inviteID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO invites (id,code_hash,max_uses,expires_at,created_at)
		VALUES ($1,$2,10,$3,$4)
	`, inviteID, "backfill-"+uuid.NewString(), now.Add(24*time.Hour), now.Add(-4*24*time.Hour)); err != nil {
		t.Fatalf("insert backfill invite: %v", err)
	}
	pendingUserID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role) VALUES ($1,$2,'pending','user')
	`, pendingUserID, "stats-backfill-"+uuid.NewString()[:8]); err != nil {
		t.Fatalf("insert backfill pending user: %v", err)
	}
	directCompletedAt := now.Add(-time.Hour)
	expiredAt := now.Add(-2 * 24 * time.Hour)
	expiredReleasedAt := now.Add(-24 * time.Hour)
	adminReleasedAt := now.Add(-2 * time.Hour)
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO self_registrations (
			id,user_id,invite_id,status,expires_at,completed_at,released_at,release_reason,created_at,updated_at
		) VALUES
			($1,$2,$3,'pending',$4,NULL,NULL,NULL,$5,$5),
			($6,NULL,$3,'completed',$4,$7,NULL,NULL,$8,$7),
			($9,NULL,NULL,'completed',$4,$10,NULL,NULL,$10,$10),
			($11,NULL,$3,'released',$12,NULL,$13,'expired',$14,$13),
			($15,NULL,$3,'released',$16,NULL,$17,'admin_deleted',$18,$17)
	`,
		uuid.New(), pendingUserID, inviteID, now.Add(24*time.Hour), now.Add(-24*time.Hour),
		uuid.New(), now, now.Add(-24*time.Hour),
		uuid.New(), directCompletedAt,
		uuid.New(), expiredAt, expiredReleasedAt, now.Add(-3*24*time.Hour),
		uuid.New(), now.Add(24*time.Hour), adminReleasedAt, now.Add(-4*24*time.Hour),
	); err != nil {
		t.Fatalf("insert registration backfill history: %v", err)
	}
	if err := runner.Steps(1); err != nil {
		t.Fatalf("migrate observability up: %v", err)
	}

	var started, completed, expired, reserved, consumed, released, cohortStarted, cohortCompleted int64
	if err := schema.pool.QueryRow(ctx, `
		SELECT
			COALESCE(SUM(registrations_started),0),
			COALESCE(SUM(registrations_completed),0),
			COALESCE(SUM(registrations_expired),0),
			COALESCE(SUM(invites_reserved),0),
			COALESCE(SUM(invites_consumed),0),
			COALESCE(SUM(invites_released),0),
			COALESCE(SUM(cohort_started),0),
			COALESCE(SUM(cohort_completed),0)
		FROM registration_stats_daily
	`).Scan(&started, &completed, &expired, &reserved, &consumed, &released, &cohortStarted, &cohortCompleted); err != nil {
		t.Fatalf("read registration backfill totals: %v", err)
	}
	if started != 5 || completed != 2 || expired != 1 || reserved != 4 || consumed != 1 || released != 2 || cohortStarted != 5 || cohortCompleted != 2 {
		t.Fatalf("registration backfill totals=%d/%d/%d/%d/%d/%d/%d/%d", started, completed, expired, reserved, consumed, released, cohortStarted, cohortCompleted)
	}
	var expiredOnExpiryDay, releasedOnExpiryDay int64
	expiryDay := time.Date(expiredAt.Year(), expiredAt.Month(), expiredAt.Day(), 0, 0, 0, 0, time.UTC)
	if err := schema.pool.QueryRow(ctx, `
		SELECT registrations_expired,invites_released
		FROM registration_stats_daily WHERE day=$1
	`, expiryDay).Scan(&expiredOnExpiryDay, &releasedOnExpiryDay); err != nil {
		t.Fatalf("read expiration-date backfill bucket: %v", err)
	}
	if expiredOnExpiryDay != 1 || releasedOnExpiryDay != 1 {
		t.Fatalf("expiration-date bucket expired/released=%d/%d", expiredOnExpiryDay, releasedOnExpiryDay)
	}
	var releasedOnAdminDay int64
	adminReleaseDay := time.Date(adminReleasedAt.Year(), adminReleasedAt.Month(), adminReleasedAt.Day(), 0, 0, 0, 0, time.UTC)
	if err := schema.pool.QueryRow(ctx, `
		SELECT invites_released FROM registration_stats_daily WHERE day=$1
	`, adminReleaseDay).Scan(&releasedOnAdminDay); err != nil {
		t.Fatalf("read active-release backfill bucket: %v", err)
	}
	if releasedOnAdminDay != 1 {
		t.Fatalf("active-release bucket released=%d", releasedOnAdminDay)
	}
	var availableFrom time.Time
	if err := schema.pool.QueryRow(ctx, `SELECT mail_stats_available_from FROM stats_observability_state WHERE singleton=TRUE`).Scan(&availableFrom); err != nil {
		t.Fatalf("read mail observability boundary: %v", err)
	}
	if availableFrom.IsZero() {
		t.Fatal("mail observability boundary was not initialized")
	}
}

func TestRegistrationAndMailObservabilityAggregates(t *testing.T) {
	schema := newMigratedRegistrationSchema(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	createdAt := now.Add(-30 * time.Minute)
	expiresAt := now.Add(72 * time.Hour)

	_, firstInviteHash := createRegistrationTestInvite(
		t, schema, nil, 5, createdAt.Add(-time.Minute), expiresAt,
	)
	_, secondInviteHash := createRegistrationTestInvite(
		t, schema, nil, 5, now.Add(-3*time.Hour), expiresAt,
	)
	clock := createdAt
	verifyFirst := "stats-first-" + uuid.NewString()
	verifySecond := "stats-second-" + uuid.NewString()
	verifyExpired := "stats-expired-" + uuid.NewString()
	accountService := newRegistrationAccountService(
		t, schema, &clock, verifyFirst, verifySecond, verifyExpired,
	)

	first := registrationTestUser("stats-first-"+uuid.NewString()[:8], models.UserStatusPending)
	createPendingRegistration(t, schema, accountService, first, &firstInviteHash, createdAt, expiresAt)
	second := registrationTestUser("stats-second-"+uuid.NewString()[:8], models.UserStatusPending)
	createPendingRegistration(t, schema, accountService, second, nil, createdAt, expiresAt)

	expiredCreatedAt := now.Add(-2 * time.Hour)
	expiredAt := now.Add(-time.Hour)
	clock = expiredCreatedAt
	expiredUser := registrationTestUser("stats-expired-"+uuid.NewString()[:8], models.UserStatusPending)
	createPendingRegistration(t, schema, accountService, expiredUser, &secondInviteHash, expiredCreatedAt, expiredAt)

	clock = now
	if _, err := accountService.ConfirmEmailVerification(ctx, verifyFirst); err != nil {
		t.Fatalf("confirm observed registration: %v", err)
	}
	if _, err := accountService.ConfirmEmailVerification(ctx, verifyFirst); err == nil {
		t.Fatal("verification token was accepted twice")
	}
	cleanup, err := registration.NewStore(schema.pool).CleanupExpired(ctx, now, 10, 2)
	if err != nil {
		t.Fatalf("cleanup expired observed registration: %v", err)
	}
	if cleanup.Released != 1 || cleanup.DeletedUsers != 1 {
		t.Fatalf("cleanup result = %#v", cleanup)
	}

	mailUser := registrationTestUser("stats-mail-"+uuid.NewString()[:8], models.UserStatusActive)
	insertRegistrationTestUser(t, schema, mailUser)
	mailStore := account.NewStore(schema.pool)
	transientID := enqueueObservedEmail(t, schema, mailUser.ID, now, now.Add(24*time.Hour))
	setObservedEmailSending(t, schema, transientID, "stats-worker", now)
	if err := mailStore.MarkEmailFailed(ctx, transientID, "stats-worker", "SMTP transport failure", now.Add(time.Minute), now); err != nil {
		t.Fatalf("mark transient email failure: %v", err)
	}
	setObservedEmailSending(t, schema, transientID, "stats-worker", now.Add(time.Minute))
	if err := mailStore.MarkEmailSent(ctx, transientID, "stats-worker", now.Add(time.Minute)); err != nil {
		t.Fatalf("mark retried email sent: %v", err)
	}

	rejectedID := enqueueObservedEmail(t, schema, mailUser.ID, now, now.Add(24*time.Hour))
	setObservedEmailSending(t, schema, rejectedID, "stats-worker", now)
	if err := mailStore.MarkEmailRejected(ctx, rejectedID, "stats-worker", now); err != nil {
		t.Fatalf("mark rejected email: %v", err)
	}

	expiringID := enqueueObservedEmail(t, schema, mailUser.ID, now, now.Add(time.Minute))
	if expired, err := mailStore.ExpireEmailArtifacts(ctx, now.Add(2*time.Minute), 50); err != nil || expired != 1 {
		t.Fatalf("expire observed email: count=%d err=%v", expired, err)
	}
	var expiringStatus string
	if err := schema.pool.QueryRow(ctx, `SELECT status FROM email_outbox WHERE id=$1`, expiringID).Scan(&expiringStatus); err != nil {
		t.Fatalf("read expired observed email: %v", err)
	}
	if expiringStatus != "expired" {
		t.Fatalf("expired observed email status = %q", expiringStatus)
	}

	rolledBack := observedOutboxEmail(uuid.New(), mailUser.ID, now, now.Add(time.Hour))
	tx, err := schema.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin rolled-back outbox transaction: %v", err)
	}
	if err := account.EnqueueEmailTx(ctx, tx, rolledBack); err != nil {
		t.Fatalf("enqueue rolled-back observed email: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback observed email: %v", err)
	}
	if err := mailStore.MarkEmailSent(ctx, uuid.New(), "missing-worker", now); err != account.ErrOutboxLeaseLost {
		t.Fatalf("missing lease error = %v", err)
	}

	backlog, oldestAge, err := mailStore.EmailOutboxBacklog(ctx, now)
	if err != nil {
		t.Fatalf("load observed mail backlog: %v", err)
	}
	if backlog != 2 || oldestAge < 29*time.Minute {
		t.Fatalf("mail backlog=%d oldest_age=%s", backlog, oldestAge)
	}

	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	if err := session.NewStore(rdb).SaveSession(ctx, "stats-observability-session", &session.SessionData{
		UserID: mailUser.ID.String(), Username: mailUser.Username, AuthVersion: 1,
	}, time.Hour); err != nil {
		t.Fatalf("save observed active session: %v", err)
	}
	handler := dashboardstats.NewHandler(schema.pool, rdb)
	if err := handler.Refresh(ctx); err != nil {
		t.Fatalf("refresh registration and mail statistics: %v", err)
	}
	refreshResults := make(chan error, 2)
	for _, current := range []*dashboardstats.Handler{handler, dashboardstats.NewHandler(schema.pool, rdb)} {
		go func(candidate *dashboardstats.Handler) { refreshResults <- candidate.Refresh(ctx) }(current)
	}
	for range 2 {
		if err := <-refreshResults; err != nil {
			t.Fatalf("concurrent HA statistics refresh: %v", err)
		}
	}

	statsRecorder := httptest.NewRecorder()
	handler.GetStats(statsRecorder, httptest.NewRequest(http.MethodGet, "/api/admin/stats", nil))
	if statsRecorder.Code != http.StatusOK {
		t.Fatalf("stats status=%d body=%s", statsRecorder.Code, statsRecorder.Body.String())
	}
	var snapshot models.DashboardStats
	if err := json.Unmarshal(statsRecorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode observed snapshot: %v", err)
	}
	if snapshot.ActiveSessions != 1 || snapshot.PendingRegistrations != 1 || snapshot.CompletedRegistrations7d != 1 ||
		snapshot.MailBacklog != 2 || snapshot.MailFailures24h != 2 || snapshot.SMTPCircuitState != "closed" {
		t.Fatalf("observed snapshot = %#v", snapshot)
	}
	if snapshot.RegistrationCompletionRate30d == nil || math.Abs(*snapshot.RegistrationCompletionRate30d-(1.0/3.0)) > 0.000001 {
		t.Fatalf("registration completion rate = %v", snapshot.RegistrationCompletionRate30d)
	}
	if snapshot.MailStatsAvailableFrom.IsZero() || snapshot.RefreshedAt.IsZero() {
		t.Fatalf("observability timestamps = available:%s refreshed:%s", snapshot.MailStatsAvailableFrom, snapshot.RefreshedAt)
	}

	userBeforeRedisFailure := snapshot.UserCount
	extraUser := registrationTestUser("stats-redis-fallback-"+uuid.NewString()[:8], models.UserStatusActive)
	insertRegistrationTestUser(t, schema, extraUser)
	mini.Close()
	if err := handler.Refresh(ctx); err != nil {
		t.Fatalf("refresh PostgreSQL statistics while Redis is unavailable: %v", err)
	}
	preservedRecorder := httptest.NewRecorder()
	handler.GetStats(preservedRecorder, httptest.NewRequest(http.MethodGet, "/api/admin/stats", nil))
	if err := json.Unmarshal(preservedRecorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode Redis-fallback snapshot: %v", err)
	}
	if snapshot.UserCount != userBeforeRedisFailure+1 || snapshot.ActiveSessions != 1 {
		t.Fatalf("Redis-fallback snapshot = %#v", snapshot)
	}

	registrationRecorder := httptest.NewRecorder()
	handler.GetRegistrationTrend(registrationRecorder, httptest.NewRequest(http.MethodGet, "/api/admin/stats/registration-trend?days=7", nil))
	if registrationRecorder.Code != http.StatusOK {
		t.Fatalf("registration trend status=%d body=%s", registrationRecorder.Code, registrationRecorder.Body.String())
	}
	var registrationTrend models.RegistrationTrend
	if err := json.Unmarshal(registrationRecorder.Body.Bytes(), &registrationTrend); err != nil {
		t.Fatalf("decode registration trend: %v", err)
	}
	var started, completed, expired, reserved, consumed, released int64
	for _, point := range registrationTrend.Points {
		started += point.RegistrationsStarted
		completed += point.RegistrationsCompleted
		expired += point.RegistrationsExpired
		reserved += point.InvitesReserved
		consumed += point.InvitesConsumed
		released += point.InvitesReleased
	}
	if len(registrationTrend.Points) != 7 || registrationTrend.Timezone != "UTC" ||
		started != 3 || completed != 1 || expired != 1 || reserved != 2 || consumed != 1 || released != 1 {
		t.Fatalf("registration trend = %#v totals=%d/%d/%d/%d/%d/%d", registrationTrend, started, completed, expired, reserved, consumed, released)
	}

	mailRecorder := httptest.NewRecorder()
	handler.GetMailTrend(mailRecorder, httptest.NewRequest(http.MethodGet, "/api/admin/stats/mail-trend?days=7", nil))
	if mailRecorder.Code != http.StatusOK {
		t.Fatalf("mail trend status=%d body=%s", mailRecorder.Code, mailRecorder.Body.String())
	}
	var mailTrend models.MailTrend
	if err := json.Unmarshal(mailRecorder.Body.Bytes(), &mailTrend); err != nil {
		t.Fatalf("decode mail trend: %v", err)
	}
	var enqueued, sent, otherFailures, rejected, mailExpired int64
	for _, point := range mailTrend.Points {
		enqueued += point.Enqueued
		sent += point.Sent
		otherFailures += point.OtherFailures
		rejected += point.Rejected
		mailExpired += point.Expired
	}
	if len(mailTrend.Points) != 7 || mailTrend.Timezone != "UTC" || mailTrend.AvailableFrom.IsZero() ||
		enqueued != 6 || sent != 1 || otherFailures != 1 || rejected != 1 || mailExpired != 1 {
		t.Fatalf("mail trend = %#v totals=%d/%d/%d/%d/%d", mailTrend, enqueued, sent, otherFailures, rejected, mailExpired)
	}
	invalidRecorder := httptest.NewRecorder()
	handler.GetMailTrend(invalidRecorder, httptest.NewRequest(http.MethodGet, "/api/admin/stats/mail-trend?days=6", nil))
	if invalidRecorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid trend range status=%d body=%s", invalidRecorder.Code, invalidRecorder.Body.String())
	}
}

func enqueueObservedEmail(t *testing.T, schema *postgresTestSchema, userID uuid.UUID, createdAt, expiresAt time.Time) uuid.UUID {
	t.Helper()
	email := observedOutboxEmail(uuid.New(), userID, createdAt, expiresAt)
	tx, err := schema.pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin observed outbox transaction: %v", err)
	}
	defer tx.Rollback(context.Background())
	if err := account.EnqueueEmailTx(context.Background(), tx, email); err != nil {
		t.Fatalf("enqueue observed email: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit observed email: %v", err)
	}
	return email.ID
}

func observedOutboxEmail(id, userID uuid.UUID, createdAt, expiresAt time.Time) *account.OutboxEmail {
	return &account.OutboxEmail{
		ID: id, UserID: &userID, MessageType: account.MessageEmailVerification,
		RecipientHash: make([]byte, 32), EncryptedMessage: "opaque-observed-envelope",
		AvailableAt: createdAt.UTC(), ExpiresAt: expiresAt.UTC(), CreatedAt: createdAt.UTC(),
	}
}

func setObservedEmailSending(t *testing.T, schema *postgresTestSchema, id uuid.UUID, worker string, now time.Time) {
	t.Helper()
	if _, err := schema.pool.Exec(context.Background(), `
		UPDATE email_outbox
		SET status='sending',locked_at=$3,locked_by=$2,updated_at=$3
		WHERE id=$1
	`, id, worker, now.UTC()); err != nil {
		t.Fatalf("set observed email sending: %v", err)
	}
}
