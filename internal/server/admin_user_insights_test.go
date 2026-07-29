package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestAdminUserInsightsHTTPContract(t *testing.T) {
	cluster := newHAHTTPTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), haIntegrationTimeout)
	defer cancel()

	marker := strings.ReplaceAll(uuid.NewString(), "-", "")
	const password = "admin-insights-password-123"
	admin, err := cluster.apps[0].userService.Create(ctx, models.CreateUserRequest{
		Username: "insights_admin_" + marker, Password: password,
	})
	if err != nil {
		t.Fatalf("create administrator fixture: %v", err)
	}
	if _, err := cluster.apps[0].db.Exec(ctx, `UPDATE users SET role='admin' WHERE id=$1`, admin.ID); err != nil {
		t.Fatalf("promote administrator fixture: %v", err)
	}
	adminLogin := cluster.login(t, 0, admin.Username, password, "198.51.100.90")

	requestBody, err := json.Marshal(models.CreateUserRequest{
		Username: "insights_user_" + marker, Email: "insights-" + marker + "@example.test",
		Password: password, DisplayName: "Managed User",
	})
	if err != nil {
		t.Fatalf("encode administrator user creation: %v", err)
	}
	response := cluster.request(
		t, 1, http.MethodPost, "/api/admin/users", bytes.NewReader(requestBody),
		adminLogin.cookie, adminLogin.session.CSRFToken, "198.51.100.90",
	)
	if response.StatusCode != http.StatusCreated {
		body := readHAResponse(t, response)
		t.Fatalf("administrator user creation status=%d body=%s", response.StatusCode, body)
	}
	var created models.User
	decodeHAResponse(t, response, &created)

	var creationSource string
	var createdBy *uuid.UUID
	if err := cluster.apps[0].db.QueryRow(ctx, `
		SELECT creation_source,created_by FROM users WHERE id=$1
	`, created.ID).Scan(&creationSource, &createdBy); err != nil {
		t.Fatalf("load user creation provenance: %v", err)
	}
	if creationSource != "admin" || createdBy == nil || *createdBy != admin.ID {
		t.Fatalf("creation provenance source=%q created_by=%v", creationSource, createdBy)
	}
	var auditActor, auditTarget string
	if err := cluster.apps[0].db.QueryRow(ctx, `
		SELECT payload->>'actor_id',payload->>'target_id'
		FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='user' AND aggregate_id=$2
		ORDER BY created_at DESC LIMIT 1
	`, models.AuditUserCreated, created.ID.String()).Scan(&auditActor, &auditTarget); err != nil {
		t.Fatalf("load transactional user creation audit: %v", err)
	}
	if auditActor != admin.ID.String() || auditTarget != created.ID.String() {
		t.Fatalf("creation audit actor=%q target=%q", auditActor, auditTarget)
	}

	ownerID := created.ID.String()
	clientMutation := audit.MutationAudit{
		Event: models.AuditClientCreated, ActorID: admin.ID, ActorName: admin.Username,
		Result: "success", RiskLevel: "low", IPAddress: "198.51.100.90", UserAgent: "Nyauth-Insights-Test/1.0",
	}
	activeClient, err := cluster.apps[0].clientService.CreateAdmin(ctx, models.CreateClientRequest{
		Name: "Active authorization", RedirectURIs: []string{"https://client.example/active"},
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"openid", "profile"},
		IsPublic: true, OwnerID: &ownerID,
	}, clientMutation)
	if err != nil {
		t.Fatalf("create active client: %v", err)
	}
	revokedClient, err := cluster.apps[0].clientService.CreateAdmin(ctx, models.CreateClientRequest{
		Name: "Revoked authorization", RedirectURIs: []string{"https://client.example/revoked"},
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"openid"},
		IsPublic: true, OwnerID: &ownerID,
	}, clientMutation)
	if err != nil {
		t.Fatalf("create revoked client: %v", err)
	}
	grantedAt := time.Now().UTC().Add(-time.Minute)
	if err := cluster.apps[0].authorizationStore.Upsert(ctx, created.ID, activeClient.ID, []string{"openid", "profile"}, grantedAt); err != nil {
		t.Fatalf("create active authorization: %v", err)
	}
	if err := cluster.apps[0].authorizationStore.Upsert(ctx, created.ID, revokedClient.ID, []string{"openid"}, grantedAt); err != nil {
		t.Fatalf("create revoked authorization: %v", err)
	}
	if _, err := cluster.apps[0].sessionStore.RevokeUserClientAuthorization(ctx, created.ID.String(), revokedClient.ID, time.Hour); err != nil {
		t.Fatalf("mark authorization revoked: %v", err)
	}
	revocationDigest := haDigest(created.ID.String() + "\x00" + revokedClient.ID)
	cluster.trackRedisKey("nyauth:authorization-clock:" + revocationDigest)
	cluster.trackRedisKey("nyauth:authorization-revoked:" + revocationDigest)

	actorName := created.Username
	targetType := "user"
	targetID := created.ID.String()
	userAgent := "Nyauth-Insights-Test/1.0"
	if err := cluster.apps[0].auditStore.Record(ctx, &models.AuditLog{
		ID: uuid.New(), Event: models.AuditUserLogin, ActorID: &created.ID, ActorName: &actorName,
		Result: "success", RiskLevel: "low", UserAgent: &userAgent,
		Details: map[string]interface{}{"source": "password"}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("record actor activity: %v", err)
	}
	if err := cluster.apps[0].auditStore.Record(ctx, &models.AuditLog{
		ID: uuid.New(), Event: models.AuditUserUpdated, ActorID: &admin.ID,
		TargetType: &targetType, TargetID: &targetID, Result: "success", RiskLevel: "medium",
		Details: map[string]interface{}{}, CreatedAt: time.Now().UTC().Add(-time.Second),
	}); err != nil {
		t.Fatalf("record target activity: %v", err)
	}
	unrelatedID := uuid.New().String()
	if err := cluster.apps[0].auditStore.Record(ctx, &models.AuditLog{
		ID: uuid.New(), Event: models.AuditUserUpdated, ActorID: &admin.ID,
		TargetType: &targetType, TargetID: &unrelatedID, Result: "success", RiskLevel: "low",
		Details: map[string]interface{}{}, CreatedAt: time.Now().UTC().Add(-2 * time.Second),
	}); err != nil {
		t.Fatalf("record unrelated activity: %v", err)
	}

	basePath := "/api/admin/users/" + created.ID.String()
	response = cluster.request(t, 0, http.MethodGet, basePath+"/overview", nil, adminLogin.cookie, "", "198.51.100.90")
	assertAdminInsightsNoStore(t, response)
	var overview user.AdminUserOverview
	decodeHAResponse(t, response, &overview)
	if overview.User.ID != created.ID || overview.CreationSource != "admin" || overview.SelfRegistration != nil ||
		overview.CreatedBy == nil || overview.CreatedBy.ID != admin.ID {
		t.Fatalf("overview = %#v", overview)
	}

	response = cluster.request(t, 1, http.MethodGet, basePath+"/security", nil, adminLogin.cookie, "", "198.51.100.90")
	assertAdminInsightsNoStore(t, response)
	var security user.AdminUserSecurity
	decodeHAResponse(t, response, &security)
	if !security.HasPassword || !security.TOTPAvailable || !security.PasskeysAvailable ||
		security.TOTPEnrolled || security.PasskeysEnrolled != 0 || security.PasskeyCloneWarnings != 0 {
		t.Fatalf("security = %#v", security)
	}

	response = cluster.request(t, 0, http.MethodGet, basePath+"/authorizations", nil, adminLogin.cookie, "", "198.51.100.90")
	assertAdminInsightsNoStore(t, response)
	var authorizations []adminUserAuthorization
	decodeHAResponse(t, response, &authorizations)
	if len(authorizations) != 1 || authorizations[0].ClientID != activeClient.ID {
		t.Fatalf("effective authorizations = %#v", authorizations)
	}

	response = cluster.request(t, 1, http.MethodGet, basePath+"/clients?page=1&page_size=20", nil, adminLogin.cookie, "", "198.51.100.90")
	assertAdminInsightsNoStore(t, response)
	var clients models.PaginatedResponse[adminUserClientSummary]
	var clientPage clientQuotaPage[adminUserClientSummary]
	decodeHAResponse(t, response, &clientPage)
	clients = *clientPage.PaginatedResponse
	if clients.Total != 2 || len(clients.Items) != 2 {
		t.Fatalf("owned clients = %#v", clients)
	}
	if clientPage.OwnerQuota == nil || clientPage.Used != 2 || clientPage.Limit != 10 || clientPage.Override != nil {
		t.Fatalf("client quota = %#v", clientPage.OwnerQuota)
	}

	response = cluster.request(t, 0, http.MethodPut, basePath+"/client-quota", strings.NewReader(`{"quota_override":1}`), adminLogin.cookie, adminLogin.session.CSRFToken, "198.51.100.90")
	if response.StatusCode != http.StatusOK {
		body := readHAResponse(t, response)
		t.Fatalf("update client quota status=%d body=%s", response.StatusCode, body)
	}
	var updatedQuota client.OwnerQuota
	decodeHAResponse(t, response, &updatedQuota)
	if updatedQuota.Used != 2 || updatedQuota.Limit != 1 || updatedQuota.Override == nil || *updatedQuota.Override != 1 {
		t.Fatalf("updated client quota = %#v", updatedQuota)
	}
	var quotaAuditCount int
	if err := cluster.apps[0].db.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='user' AND aggregate_id=$2
	`, models.AuditUserClientQuotaUpdated, created.ID.String()).Scan(&quotaAuditCount); err != nil {
		t.Fatalf("count quota audit rows: %v", err)
	}
	if quotaAuditCount != 1 {
		t.Fatalf("quota audit rows = %d, want 1", quotaAuditCount)
	}

	response = cluster.request(t, 0, http.MethodGet, basePath+"/activity?page=1&page_size=20", nil, adminLogin.cookie, "", "198.51.100.90")
	assertAdminInsightsNoStore(t, response)
	var activity models.PaginatedResponse[adminUserActivity]
	decodeHAResponse(t, response, &activity)
	if activity.Total != 2 || len(activity.Items) != 2 {
		t.Fatalf("user activity = %#v", activity)
	}
	if activity.Items[0].UserAgent == nil || *activity.Items[0].UserAgent != userAgent {
		t.Fatalf("protected user agent missing from activity: %#v", activity.Items[0])
	}
}

func assertAdminInsightsNoStore(t *testing.T, response *http.Response) {
	t.Helper()
	if response.StatusCode != http.StatusOK {
		body := readHAResponse(t, response)
		t.Fatalf("admin insights status=%d body=%s", response.StatusCode, body)
	}
	if cacheControl := response.Header.Get("Cache-Control"); !strings.Contains(cacheControl, "no-store") {
		_ = readHAResponse(t, response)
		t.Fatalf("Cache-Control = %q, want no-store", cacheControl)
	}
}
