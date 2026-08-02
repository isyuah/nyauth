package deviceauthorization

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func testStore(t *testing.T) (*Store, *miniredis.Miniredis, *time.Time) {
	t.Helper()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	store := NewStore(rdb)
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	return store, mini, &now
}

func createPending(t *testing.T, store *Store) *Created {
	t.Helper()
	created, err := store.Create(context.Background(), CreateInput{
		ClientID: "television", Scopes: []string{"openid", "profile"}, OptionalScopes: []string{"profile"},
		ScopeClaims:            map[string][]string{"openid": {"sub"}, "profile": {"name"}},
		ClientIdentityRevision: 2, ClientAuthorizationRevision: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func TestCreateStoresOnlyHashedCodesAndResolvesNormalizedUserCode(t *testing.T) {
	store, mini, _ := testStore(t)
	created := createPending(t, store)
	if len(created.DeviceCode) < 40 || len(created.UserCode) != 9 || created.UserCode[4] != '-' {
		t.Fatalf("unexpected generated codes: device length=%d user=%q", len(created.DeviceCode), created.UserCode)
	}
	for _, key := range mini.Keys() {
		if strings.Contains(key, created.DeviceCode) || strings.Contains(key, created.UserCode) {
			t.Fatalf("raw bearer value leaked into Redis key %q", key)
		}
	}
	resolved, err := store.FindPendingByUserCode(context.Background(), strings.ToLower(strings.ReplaceAll(created.UserCode, "-", " ")))
	if err != nil {
		t.Fatal(err)
	}
	if resolved.DeviceID != created.Record.DeviceID || resolved.ClientAuthorizationRevision != 3 {
		t.Fatalf("resolved record = %#v", resolved)
	}
}

func TestPollCadenceApprovalAndSingleConsumption(t *testing.T) {
	store, _, now := testStore(t)
	created := createPending(t, store)

	if _, retry, err := store.Poll(context.Background(), created.DeviceCode, "television"); !errors.Is(err, ErrSlowDown) || retry != 10*time.Second {
		t.Fatalf("first early poll = retry %s err %v", retry, err)
	}
	*now = now.Add(10 * time.Second)
	if _, retry, err := store.Poll(context.Background(), created.DeviceCode, "television"); !errors.Is(err, ErrAuthorizationPending) || retry != 10*time.Second {
		t.Fatalf("on-time pending poll = retry %s err %v", retry, err)
	}

	current, err := store.FindPendingByUserCode(context.Background(), created.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(context.Background(), current, "user-1", 7, []string{"openid"}, []string{"sub"}, 1234); err != nil {
		t.Fatal(err)
	}
	approved, _, err := store.Poll(context.Background(), created.DeviceCode, "television")
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != StatusApproved || approved.UserID != "user-1" || approved.AuthVersion != 7 {
		t.Fatalf("approved record = %#v", approved)
	}

	var successes atomic.Int32
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			if store.ConsumeApproved(context.Background(), approved) == nil {
				successes.Add(1)
			}
		}()
	}
	group.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful consumes = %d, want 1", successes.Load())
	}
	if _, _, err := store.Poll(context.Background(), created.DeviceCode, "television"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consumed device code remained usable: %v", err)
	}
}

func TestApprovalPreservesExactAuthorizationTimestamp(t *testing.T) {
	store, mini, _ := testStore(t)
	created := createPending(t, store)
	current, err := store.FindPendingByUserCode(context.Background(), created.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	const issuedAt int64 = 1_785_656_294_708_237
	if err := store.Approve(context.Background(), current, "user-1", 7, []string{"openid"}, []string{"sub"}, issuedAt); err != nil {
		t.Fatal(err)
	}
	raw, err := mini.Get(recordKey(created.Record.DeviceID))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, `"authorization_issued_at":1785656294708237`) || strings.Contains(strings.ToLower(raw), "e+") {
		t.Fatalf("approval timestamp was not preserved as an exact JSON integer: %s", raw)
	}
	approved, _, err := store.Poll(context.Background(), created.DeviceCode, "television")
	if err != nil {
		t.Fatal(err)
	}
	if approved.AuthorizationIssuedAt != issuedAt {
		t.Fatalf("authorization issued at = %d, want %d", approved.AuthorizationIssuedAt, issuedAt)
	}
}

func TestDenyAndClientBinding(t *testing.T) {
	store, _, _ := testStore(t)
	created := createPending(t, store)
	if _, _, err := store.Poll(context.Background(), created.DeviceCode, "another-client"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("client mismatch error = %v", err)
	}
	current, err := store.FindPendingByUserCode(context.Background(), created.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Deny(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindPendingByUserCode(context.Background(), created.UserCode); !errors.Is(err, ErrNotFound) {
		t.Fatalf("denied user code remained resolvable: %v", err)
	}
	if _, _, err := store.Poll(context.Background(), created.DeviceCode, "television"); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("denied poll error = %v", err)
	}
	if _, _, err := store.Poll(context.Background(), created.DeviceCode, "television"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("denial was not consumed: %v", err)
	}
}

func TestAuthorizationExpiresFromBothIndexes(t *testing.T) {
	store, mini, now := testStore(t)
	created := createPending(t, store)

	*now = now.Add(DefaultTTL + time.Second)
	mini.FastForward(DefaultTTL + time.Second)
	if _, err := store.FindPendingByUserCode(context.Background(), created.UserCode); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired user code error = %v", err)
	}
	if _, _, err := store.Poll(context.Background(), created.DeviceCode, "television"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired device code error = %v", err)
	}
}

func TestApprovalAndConsumptionAreSharedAcrossStoreInstances(t *testing.T) {
	storeA, mini, now := testStore(t)
	rdbB := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdbB.Close() })
	storeB := NewStore(rdbB)
	storeB.now = func() time.Time { return *now }

	created := createPending(t, storeA)
	current, err := storeB.FindPendingByUserCode(context.Background(), created.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	if err := storeB.Approve(context.Background(), current, "user-1", 7, []string{"openid"}, []string{"sub"}, 1234); err != nil {
		t.Fatal(err)
	}
	approved, _, err := storeA.Poll(context.Background(), created.DeviceCode, "television")
	if err != nil {
		t.Fatal(err)
	}
	if err := storeA.ConsumeApproved(context.Background(), approved); err != nil {
		t.Fatal(err)
	}
	if err := storeB.ConsumeApproved(context.Background(), approved); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second instance consumed the same approval: %v", err)
	}
}

func TestVerificationLimiterIsSharedBySubjectAndIP(t *testing.T) {
	store, _, _ := testStore(t)
	ctx := context.Background()
	for index := 0; index < 10; index++ {
		if retry, err := store.ReserveVerification(ctx, "user-1", "192.0.2.10"); err != nil || retry != 0 {
			t.Fatalf("attempt %d = retry %s err %v", index, retry, err)
		}
	}
	if retry, err := store.ReserveVerification(ctx, "user-1", "192.0.2.11"); !errors.Is(err, ErrRateLimited) || retry <= 0 {
		t.Fatalf("subject limit = retry %s err %v", retry, err)
	}
}

func TestRedisIntegrationApprovalPreservesExactAuthorizationTimestamp(t *testing.T) {
	addr := strings.TrimSpace(os.Getenv("NYAUTH_TEST_REDIS_ADDR"))
	if addr == "" {
		t.Skip("NYAUTH_TEST_REDIS_ADDR is not set; skipping Redis integration test")
	}
	database := 0
	if configured := strings.TrimSpace(os.Getenv("NYAUTH_TEST_REDIS_DB")); configured != "" {
		parsed, err := strconv.Atoi(configured)
		if err != nil || parsed < 0 {
			t.Fatalf("invalid NYAUTH_TEST_REDIS_DB %q", configured)
		}
		database = parsed
	}
	rdb := redis.NewClient(&redis.Options{
		Addr: addr, Username: os.Getenv("NYAUTH_TEST_REDIS_USERNAME"),
		Password: os.Getenv("NYAUTH_TEST_REDIS_PASSWORD"), DB: database,
	})
	t.Cleanup(func() { _ = rdb.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Fatalf("connect to integration Redis: %v", err)
	}
	unique, err := randomBase64URL(12)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(rdb)
	created, err := store.Create(ctx, CreateInput{ClientID: "device-integration-" + unique, Scopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := rdb.Del(cleanupContext, recordKey(created.Record.DeviceID), userCodeKey(created.Record.UserCodeDigest)).Err(); err != nil {
			t.Errorf("remove device authorization integration keys: %v", err)
		}
	})
	current, err := store.FindPendingByUserCode(ctx, created.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	const issuedAt int64 = 1_785_656_294_708_237
	if err := store.Approve(ctx, current, "integration-user-"+unique, 7, []string{"openid"}, []string{"sub"}, issuedAt); err != nil {
		t.Fatal(err)
	}
	approved, _, err := store.Poll(ctx, created.DeviceCode, "device-integration-"+unique)
	if err != nil {
		t.Fatal(err)
	}
	if approved.AuthorizationIssuedAt != issuedAt {
		t.Fatalf("authorization issued at = %d, want %d", approved.AuthorizationIssuedAt, issuedAt)
	}
}
