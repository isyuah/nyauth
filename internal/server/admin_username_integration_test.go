package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestSelfProfileUpdateRejectsUsername(t *testing.T) {
	current := &models.User{ID: uuid.New(), Username: "ordinary-user", Status: models.UserStatusActive, Role: "user"}
	request := httptest.NewRequest(http.MethodPut, "/api/me", bytes.NewBufferString(`{"username":"self-renamed"}`))
	request = request.WithContext(context.WithValue(request.Context(), currentUserContextKey, current))
	response := httptest.NewRecorder()

	(&Server{}).handleUpdateMe(response, request)

	if response.Code != http.StatusBadRequest || !bytes.Contains(response.Body.Bytes(), []byte(`"error":"invalid request body"`)) {
		t.Fatalf("self-service username change status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAdminUsernameChangeRequiresRecentAuthentication(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	ctx := context.Background()
	actor := &models.User{
		ID: uuid.New(), Username: "rename-admin", Status: models.UserStatusActive,
		Role: "admin", AuthVersion: 1, SessionVersion: 1, Metadata: map[string]string{},
	}
	target := &models.User{
		ID: uuid.New(), Username: "rename-target", Status: models.UserStatusActive,
		Role: "user", AuthVersion: 5, SessionVersion: 4, Metadata: map[string]string{},
	}
	if _, err := testApp.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,auth_version,session_version,metadata,creation_source)
		VALUES ($1,$2,'active','admin',1,1,'{}'::jsonb,'legacy'),
		       ($3,$4,'active','user',5,4,'{}'::jsonb,'legacy')
	`, actor.ID, actor.Username, target.ID, target.Username); err != nil {
		t.Fatalf("insert username management users: %v", err)
	}

	request := func(body string, authenticatedAt time.Time) *http.Request {
		r := httptest.NewRequest(http.MethodPut, "/api/admin/users/"+target.ID.String(), bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		routeContext := chi.NewRouteContext()
		routeContext.URLParams.Add("id", target.ID.String())
		requestContext := context.WithValue(r.Context(), chi.RouteCtxKey, routeContext)
		requestContext = context.WithValue(requestContext, currentUserContextKey, actor)
		requestContext = withAuthenticatedSession(requestContext, &AuthenticatedSession{
			ID: "rename-admin-session",
			Data: &session.SessionData{
				UserID: actor.ID.String(), Username: actor.Username, AuthVersion: 1, SessionVersion: 1,
				AuthenticatedAt: authenticatedAt,
			},
		})
		requestContext = audit.WithMutationAudit(requestContext, audit.MutationAudit{
			Event: models.AuditUserUpdated, ActorID: actor.ID, ActorName: actor.Username,
			TargetType: "user", TargetID: target.ID.String(), Result: "success", RiskLevel: "high",
		})
		return r.WithContext(requestContext)
	}

	staleRename := httptest.NewRecorder()
	testApp.app.handleAdminUpdateUser(staleRename, request(`{"username":"renamed-target"}`, time.Now().Add(-11*time.Minute)))
	if staleRename.Code != http.StatusForbidden || !bytes.Contains(staleRename.Body.Bytes(), []byte(`"code":"auth.recent_authentication_required"`)) {
		t.Fatalf("stale username change status=%d body=%s", staleRename.Code, staleRename.Body.String())
	}

	ordinaryUpdate := httptest.NewRecorder()
	testApp.app.handleAdminUpdateUser(ordinaryUpdate, request(`{"display_name":"No reauthentication needed"}`, time.Now().Add(-11*time.Minute)))
	if ordinaryUpdate.Code != http.StatusOK {
		t.Fatalf("ordinary profile update status=%d body=%s", ordinaryUpdate.Code, ordinaryUpdate.Body.String())
	}

	recentRename := httptest.NewRecorder()
	testApp.app.handleAdminUpdateUser(recentRename, request(`{"username":"renamed-target"}`, time.Now()))
	if recentRename.Code != http.StatusOK {
		t.Fatalf("recent username change status=%d body=%s", recentRename.Code, recentRename.Body.String())
	}
	var username string
	var authVersion, sessionVersion int64
	if err := testApp.pool.QueryRow(ctx, `SELECT username,auth_version,session_version FROM users WHERE id=$1`, target.ID).Scan(&username, &authVersion, &sessionVersion); err != nil {
		t.Fatal(err)
	}
	if username != "renamed-target" || authVersion != 5 || sessionVersion != 4 {
		t.Fatalf("renamed account username=%q auth_version=%d session_version=%d", username, authVersion, sessionVersion)
	}
}
