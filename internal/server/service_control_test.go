package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/servicecontrol"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

type fakeServiceControlRuntime struct {
	mu             sync.Mutex
	snapshot       servicecontrol.Snapshot
	changes        chan struct{}
	effectiveAtNow bool
	state          servicecontrol.State
	failClosed     bool
	acquireErr     error
	acquired       [][]servicecontrol.Capability
	releases       int
	updateErr      error
	updateCalled   bool
	updateRevision int64
	updateRequest  servicecontrol.UpdateRequest
}

func (f *fakeServiceControlRuntime) Start(context.Context) error { return nil }
func (f *fakeServiceControlRuntime) Acquire(capabilities ...servicecontrol.Capability) (func(), error) {
	f.acquired = append(f.acquired, append([]servicecontrol.Capability(nil), capabilities...))
	if f.acquireErr != nil {
		return nil, f.acquireErr
	}
	return func() { f.releases++ }, nil
}
func (f *fakeServiceControlRuntime) Snapshot() servicecontrol.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.effectiveAtNow {
		return f.snapshot.EffectiveAt(time.Now().UTC())
	}
	return f.snapshot
}
func (f *fakeServiceControlRuntime) Changes() <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.changes
}
func (f *fakeServiceControlRuntime) FailClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.failClosed
}
func (f *fakeServiceControlRuntime) Status(context.Context) (servicecontrol.State, error) {
	return f.state, nil
}
func (f *fakeServiceControlRuntime) Update(_ context.Context, revision int64, request servicecontrol.UpdateRequest, _ audit.MutationAudit) (servicecontrol.State, error) {
	f.updateCalled, f.updateRevision, f.updateRequest = true, revision, request
	return f.state, f.updateErr
}

func (f *fakeServiceControlRuntime) publish(snapshot servicecontrol.Snapshot) {
	f.mu.Lock()
	previous := f.changes
	f.snapshot = snapshot
	f.changes = make(chan struct{})
	f.mu.Unlock()
	if previous != nil {
		close(previous)
	}
}

func TestCapabilityMiddlewareCoversFixedCapabilities(t *testing.T) {
	for _, capability := range servicecontrol.AllCapabilities() {
		t.Run(string(capability), func(t *testing.T) {
			runtime := &fakeServiceControlRuntime{}
			server := &Server{serviceControl: runtime}
			called := false
			handler := server.capabilityMiddleware(capability)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/representative", nil))
			if recorder.Code != http.StatusNoContent || !called || runtime.releases != 1 || len(runtime.acquired) != 1 || runtime.acquired[0][0] != capability {
				t.Fatalf("status=%d called=%v releases=%d acquired=%v", recorder.Code, called, runtime.releases, runtime.acquired)
			}
		})
	}
}

func TestCapabilityMiddlewareReturnsStablePausedError(t *testing.T) {
	runtime := &fakeServiceControlRuntime{acquireErr: &servicecontrol.PausedError{
		Capabilities: []servicecontrol.Capability{servicecontrol.CapabilityAuthIssuance},
		RetryAfter:   90*time.Second + time.Millisecond,
	}}
	server := &Server{serviceControl: runtime}
	called := false
	handler := server.capabilityMiddleware(servicecontrol.CapabilityAuthIssuance)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/login", nil))
	if recorder.Code != http.StatusServiceUnavailable || called || recorder.Header().Get("Retry-After") != "91" {
		t.Fatalf("status=%d called=%v retry=%q", recorder.Code, called, recorder.Header().Get("Retry-After"))
	}
	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response["code"] != "service.capability_paused" {
		t.Fatalf("response=%s err=%v", recorder.Body.String(), err)
	}
}

func TestPublicServiceStatusIsRedactedAndDerived(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour)
	updater := "admin"
	server := &Server{serviceControl: &fakeServiceControlRuntime{snapshot: servicecontrol.Snapshot{
		Revision: 7,
		PausedCapabilities: []servicecontrol.Capability{
			servicecontrol.CapabilitySelfRegistration,
			servicecontrol.CapabilityAuthIssuance,
		},
		PublicMessage: "计划维护", InternalReason: "ticket SECRET-42", ExpiresAt: &expires,
		UpdatedByName: &updater,
	}}}
	recorder := httptest.NewRecorder()
	server.handleServiceStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/service-status", nil))
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(body, `"status":"authentication_paused"`) ||
		strings.Contains(body, "SECRET-42") || strings.Contains(body, "admin") || strings.Contains(body, `"revision"`) {
		t.Fatalf("headers=%v body=%s", recorder.Header(), body)
	}
}

func TestPublicServiceStatusReportsFailClosedAsFullPause(t *testing.T) {
	server := &Server{serviceControl: &fakeServiceControlRuntime{failClosed: true}}
	recorder := httptest.NewRecorder()
	server.handleServiceStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/service-status", nil))
	var response publicServiceStatusResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "full_pause" || len(response.PausedCapabilities) != len(servicecontrol.AllCapabilities()) || response.RetryAfterSeconds != 60 {
		t.Fatalf("response=%#v", response)
	}
}

func TestServiceStatusEventsPushesRedactedUpdatesOnOneConnection(t *testing.T) {
	updater := "admin"
	runtime := &fakeServiceControlRuntime{changes: make(chan struct{}), snapshot: servicecontrol.Snapshot{
		Revision: 1, PausedCapabilities: []servicecontrol.Capability{servicecontrol.CapabilitySelfRegistration},
		PublicMessage: "维护中", InternalReason: "ticket SECRET-42", UpdatedByName: &updater,
	}}
	server := &Server{serviceControl: runtime}
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleServiceStatusEvents))
	defer httpServer.Close()

	response, err := http.Get(httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Type") != "text/event-stream" || response.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("unexpected stream headers: %v", response.Header)
	}
	reader := bufio.NewReader(response.Body)
	first := readServiceStatusEvent(t, reader)
	if !strings.Contains(first, `"status":"restricted"`) || strings.Contains(first, "SECRET-42") || strings.Contains(first, "admin") || strings.Contains(first, `"revision"`) {
		t.Fatalf("initial event was not a redacted public DTO: %s", first)
	}

	runtime.publish(servicecontrol.Snapshot{Revision: 2, PausedCapabilities: []servicecontrol.Capability{}})
	second := readServiceStatusEvent(t, reader)
	if !strings.Contains(second, `"status":"normal"`) {
		t.Fatalf("updated event = %s", second)
	}
	_ = response.Body.Close()
	deadline := time.Now().Add(time.Second)
	for server.serviceStatusStreams.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.serviceStatusStreams.Load() != 0 {
		t.Fatal("stream handler did not exit after the client disconnected")
	}
}

func TestServiceStatusEventsRefreshesAtAutomaticExpiration(t *testing.T) {
	expires := time.Now().UTC().Add(40 * time.Millisecond)
	runtime := &fakeServiceControlRuntime{
		changes: make(chan struct{}), effectiveAtNow: true,
		snapshot: servicecontrol.Snapshot{
			Revision: 1, PausedCapabilities: []servicecontrol.Capability{servicecontrol.CapabilityMediaWrites},
			PublicMessage: "短时维护", ExpiresAt: &expires,
		},
	}
	server := &Server{serviceControl: runtime}
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleServiceStatusEvents))
	defer httpServer.Close()
	response, err := http.Get(httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if first := readServiceStatusEvent(t, reader); !strings.Contains(first, `"status":"restricted"`) {
		t.Fatalf("initial event = %s", first)
	}
	if second := readServiceStatusEvent(t, reader); !strings.Contains(second, `"status":"normal"`) {
		t.Fatalf("expiration event = %s", second)
	}
}

func TestServiceStatusEventsRejectsConnectionsAboveInstanceLimit(t *testing.T) {
	server := &Server{serviceControl: &fakeServiceControlRuntime{}}
	server.serviceStatusStreams.Store(maxServiceStatusConnections)
	recorder := httptest.NewRecorder()
	server.handleServiceStatusEvents(recorder, httptest.NewRequest(http.MethodGet, serviceStatusEventsPath, nil))
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") != "5" {
		t.Fatalf("status=%d retry=%q body=%s", recorder.Code, recorder.Header().Get("Retry-After"), recorder.Body.String())
	}
}

func readServiceStatusEvent(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	var data string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading service status event: %v", err)
		}
		line = strings.TrimSpace(line)
		if line == "" && data != "" {
			return data
		}
		if strings.HasPrefix(line, "data: ") {
			data = strings.TrimPrefix(line, "data: ")
		}
	}
}

func TestMFAReauthenticationRemainsAvailableDuringIssuancePause(t *testing.T) {
	runtime := &fakeServiceControlRuntime{acquireErr: &servicecontrol.PausedError{
		Capabilities: []servicecontrol.Capability{servicecontrol.CapabilityAuthIssuance},
		RetryAfter:   time.Minute,
	}}
	server := &Server{serviceControl: runtime}
	recorder := httptest.NewRecorder()
	release, allowed := server.acquireMFAIssuance(recorder, mfaPurposeReauthentication)
	if !allowed || recorder.Code != http.StatusOK || len(runtime.acquired) != 0 {
		t.Fatalf("reauth allowed=%v status=%d acquired=%v", allowed, recorder.Code, runtime.acquired)
	}
	release()

	recorder = httptest.NewRecorder()
	if _, allowed = server.acquireMFAIssuance(recorder, mfaPurposeLogin); allowed || recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("login MFA allowed=%v status=%d", allowed, recorder.Code)
	}
}

func TestUpdateOperationsSettingsRequiresRecentAuthentication(t *testing.T) {
	runtime := &fakeServiceControlRuntime{}
	server, cleanup := newOperationsHandlerTestServer(t, runtime)
	defer cleanup()
	request := operationsAdminRequest(t, `{"expected_revision":1,"paused_capabilities":[],"public_message":"","internal_reason":"","expires_at":null}`, time.Now().Add(-11*time.Minute))
	recorder := httptest.NewRecorder()
	server.handleUpdateOperationsSettings(recorder, request)
	if recorder.Code != http.StatusForbidden || runtime.updateCalled {
		t.Fatalf("status=%d update_called=%v body=%s", recorder.Code, runtime.updateCalled, recorder.Body.String())
	}
}

func TestUpdateOperationsSettingsMapsRevisionConflict(t *testing.T) {
	runtime := &fakeServiceControlRuntime{updateErr: servicecontrol.ErrRevisionConflict}
	server, cleanup := newOperationsHandlerTestServer(t, runtime)
	defer cleanup()
	request := operationsAdminRequest(t, `{"expected_revision":4,"paused_capabilities":["self_registration"],"public_message":"维护","internal_reason":"planned maintenance","expires_at":null}`, time.Now())
	recorder := httptest.NewRecorder()
	server.handleUpdateOperationsSettings(recorder, request)
	if recorder.Code != http.StatusConflict || !runtime.updateCalled || runtime.updateRevision != 4 {
		t.Fatalf("status=%d update_called=%v revision=%d body=%s", recorder.Code, runtime.updateCalled, runtime.updateRevision, recorder.Body.String())
	}
	var response map[string]string
	_ = json.Unmarshal(recorder.Body.Bytes(), &response)
	if response["code"] != "service_control.revision_conflict" {
		t.Fatalf("response=%v", response)
	}
}

func TestUpdateOperationsSettingsReturnsApplyingState(t *testing.T) {
	now := time.Now().UTC()
	runtime := &fakeServiceControlRuntime{state: servicecontrol.State{
		Snapshot:        servicecontrol.Snapshot{Revision: 2, PausedCapabilities: []servicecontrol.Capability{servicecontrol.CapabilityAccountMutations}, UpdatedAt: now},
		ActiveInstances: 2, AppliedInstances: 1, Applied: false,
	}}
	server, cleanup := newOperationsHandlerTestServer(t, runtime)
	defer cleanup()
	request := operationsAdminRequest(t, `{"expected_revision":1,"paused_capabilities":["account_mutations"],"public_message":"维护","internal_reason":"planned maintenance","expires_at":null}`, now)
	recorder := httptest.NewRecorder()
	server.handleUpdateOperationsSettings(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response operationsSettingsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ApplicationStatus != "applying" || response.ActiveInstances != 2 || response.AppliedInstances != 1 {
		t.Fatalf("response=%#v", response)
	}
}

func newOperationsHandlerTestServer(t *testing.T, runtime *fakeServiceControlRuntime) (*Server, func()) {
	t.Helper()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	return &Server{
		serviceControl:            runtime,
		operationsSettingsLimiter: NewOperationsSettingsLimiter(rdb),
	}, func() { _ = rdb.Close() }
}

func operationsAdminRequest(t *testing.T, body string, authenticatedAt time.Time) *http.Request {
	t.Helper()
	admin := &models.User{ID: uuid.New(), Username: "admin", Role: "admin", AuthVersion: 1, SessionVersion: 1}
	request := httptest.NewRequest(http.MethodPut, "/api/admin/settings/operations", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.60:42000"
	ctx := context.WithValue(request.Context(), currentUserContextKey, admin)
	ctx = withAuthenticatedSession(ctx, &AuthenticatedSession{ID: "operations-admin-session", Data: &session.SessionData{
		UserID: admin.ID.String(), Username: admin.Username, AuthenticatedAt: authenticatedAt,
		AuthVersion: admin.AuthVersion, SessionVersion: admin.SessionVersion,
	}})
	ctx = audit.WithMutationAudit(ctx, audit.MutationAudit{
		Event: models.AuditServiceControlUpdated, ActorID: admin.ID, ActorName: admin.Username,
		Result: "success", RiskLevel: "critical", IPAddress: "192.0.2.60",
	})
	return request.WithContext(ctx)
}

var _ serviceControlRuntime = (*fakeServiceControlRuntime)(nil)
