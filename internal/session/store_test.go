package session

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func testStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewStore(client), mini
}

func TestSecretsAreHashedInRedisKeys(t *testing.T) {
	store, mini := testStore(t)
	ctx := context.Background()
	secret := "raw-session-secret"
	data := &SessionData{UserID: "user-1", Username: "alice", AuthVersion: 1}
	if err := store.SaveSession(ctx, secret, data, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSession(ctx, secret); err != nil {
		t.Fatal(err)
	}
	for _, key := range mini.Keys() {
		if strings.Contains(key, secret) {
			t.Fatalf("raw secret leaked into Redis key %q", key)
		}
	}
}

func TestAuthorizationCodeOnlyConsumesMatchingValue(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	data := &AuthorizationData{ClientID: "client-a", UserID: "user", RedirectURI: "https://app/cb", Scopes: []string{"openid"}, CodeChallenge: "challenge", ChallengeMethod: "S256"}
	if err := store.SaveAuthorizationCode(ctx, "code", data, time.Minute); err != nil {
		t.Fatal(err)
	}
	mismatch := *data
	mismatch.ClientID = "client-b"
	if _, err := store.ConsumeAuthorizationCodeIfMatch(ctx, "code", &mismatch); !errors.Is(err, ErrValueMismatch) {
		t.Fatalf("mismatch error = %v", err)
	}
	if _, err := store.GetAuthorizationCode(ctx, "code"); err != nil {
		t.Fatalf("mismatch consumed code: %v", err)
	}
	if _, err := store.ConsumeAuthorizationCodeIfMatch(ctx, "code", data); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAuthorizationCode(ctx, "code"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("code remained after consume: %v", err)
	}
}

func TestConcurrentRefreshOnlyOneSucceedsAndReuseRevokesFamily(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	data := &TokenData{ClientID: "client", UserID: "user", Scopes: []string{"offline_access"}, AuthVersion: 1}
	if err := store.SaveRefreshToken(ctx, "old-refresh", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, err := store.RotateRefreshToken(ctx, "old-refresh", "new-refresh-"+string(rune('a'+index)), data, time.Hour)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	successes := 0
	reuse := 0
	for err := range errs {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrRefreshTokenReuse) {
			reuse++
		}
	}
	if successes != 1 {
		t.Fatalf("successful rotations = %d, want 1", successes)
	}
	if reuse == 0 {
		t.Fatal("concurrent reuse was not detected")
	}
	for i := 0; i < workers; i++ {
		if _, err := store.GetRefreshToken(ctx, "new-refresh-"+string(rune('a'+i))); err == nil {
			t.Fatal("token family remained active after reuse")
		}
	}
}

func TestRefreshBindingMismatchDoesNotMutateToken(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	data := &TokenData{ClientID: "client-a", UserID: "user", Scopes: []string{"openid", "offline_access"}, AuthVersion: 1}
	if err := store.SaveRefreshToken(ctx, "refresh", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	mismatch := *data
	mismatch.ClientID = "client-b"
	if _, err := store.RotateRefreshToken(ctx, "refresh", "replacement", &mismatch, time.Hour); !errors.Is(err, ErrTokenBindingMismatch) {
		t.Fatalf("binding mismatch error = %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, "refresh"); err != nil {
		t.Fatalf("binding mismatch consumed original token: %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, "replacement"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("binding mismatch created replacement token: %v", err)
	}
}

func TestRevokingUsedRefreshTokenRevokesCurrentFamily(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	data := &TokenData{ClientID: "client", UserID: "user", Scopes: []string{"offline_access"}, AuthVersion: 1}
	if err := store.SaveRefreshToken(ctx, "old", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RotateRefreshToken(ctx, "old", "current", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeRefreshTokenForClient(ctx, "old", "client", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetRefreshToken(ctx, "current"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("current family token survived revoking used token: %v", err)
	}
}

func TestCrossClientRefreshRevocationDoesNotMutateFamily(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	data := &TokenData{ClientID: "owner", UserID: "user", Scopes: []string{"offline_access"}, AuthVersion: 1}
	if err := store.SaveRefreshToken(ctx, "refresh", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeRefreshTokenForClient(ctx, "refresh", "attacker", time.Hour); !errors.Is(err, ErrTokenBindingMismatch) {
		t.Fatalf("cross-client revoke error = %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, "refresh"); err != nil {
		t.Fatalf("cross-client revoke changed token family: %v", err)
	}
}

func TestConcurrentRefreshAndRevokeLeavesNoLiveFamilyToken(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	data := &TokenData{ClientID: "client", UserID: "user", Scopes: []string{"offline_access"}, AuthVersion: 1}
	if err := store.SaveRefreshToken(ctx, "old", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, _ = store.RotateRefreshToken(ctx, "old", "new", data, time.Hour)
	}()
	go func() {
		defer wg.Done()
		<-start
		_ = store.RevokeRefreshTokenForClient(ctx, "old", "client", time.Hour)
	}()
	close(start)
	wg.Wait()
	if _, err := store.GetRefreshToken(ctx, "old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old token survived concurrent revoke: %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, "new"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("new token survived concurrent revoke: %v", err)
	}
}

func TestRefreshFamilyRevocationDeletesDerivedAccessMetadata(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	data := &TokenData{ClientID: "client", UserID: "user", Scopes: []string{"offline_access"}, AuthVersion: 1}
	if err := store.SaveRefreshToken(ctx, "old", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	rotated, err := store.RotateRefreshToken(ctx, "old", "new", data, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	access := &TokenData{ClientID: "client", UserID: "user", Scopes: []string{"offline_access"}, TokenUse: "access", AuthVersion: 1}
	if err := store.SaveTokenForRefreshFamily(ctx, "access-jti", access, rotated.FamilyKey, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeRefreshTokenForClient(ctx, "old", "client", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetToken(ctx, "access-jti"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("derived access metadata survived family revocation: %v", err)
	}
}
