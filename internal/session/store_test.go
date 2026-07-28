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

func TestUserCanListAndRevokeSessionByPublicID(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	first := &SessionData{UserID: "user-1", Username: "alice", AuthVersion: 1, IPAddress: "192.0.2.10", UserAgent: "browser-a"}
	second := &SessionData{UserID: "user-1", Username: "alice", AuthVersion: 1, IPAddress: "192.0.2.11", UserAgent: "browser-b"}
	if err := store.SaveSession(ctx, "cookie-a", first, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSession(ctx, "cookie-b", second, time.Hour); err != nil {
		t.Fatal(err)
	}
	if first.PublicID == "" || second.PublicID == "" || first.PublicID == second.PublicID {
		t.Fatal("sessions did not receive distinct public identifiers")
	}
	items, err := store.ListUserSessions(ctx, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("session count = %d, want 2", len(items))
	}
	if err := store.DeleteUserSessionByPublicID(ctx, "user-1", first.PublicID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSession(ctx, "cookie-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked session remained available: %v", err)
	}
	if _, err := store.GetSession(ctx, "cookie-b"); err != nil {
		t.Fatalf("unrelated session was removed: %v", err)
	}
	if err := store.DeleteUserSessionByPublicID(ctx, "other-user", second.PublicID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-user revocation error = %v", err)
	}
}

func TestUpdateSessionCannotResurrectARevokedSession(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	data := &SessionData{UserID: "user-reauth", Username: "alice", AuthVersion: 2, SessionVersion: 1}
	if err := store.SaveSession(ctx, "reauth-session", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	data.AuthenticatedAt = time.Now().UTC()
	if err := store.UpdateSession(ctx, "reauth-session", data, 2, 1, time.Hour); err != nil {
		t.Fatalf("update existing session: %v", err)
	}
	data.AuthVersion = 3
	if err := store.UpdateSession(ctx, "reauth-session", data, 3, 1, time.Hour); !errors.Is(err, ErrValueMismatch) {
		t.Fatalf("concurrent security-version upgrade error=%v", err)
	}
	data.AuthVersion = 2
	if err := store.DeleteSession(ctx, "reauth-session"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateSession(ctx, "reauth-session", data, 2, 1, time.Hour); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update revoked session error=%v", err)
	}
	if _, err := store.GetSession(ctx, "reauth-session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked session was recreated: %v", err)
	}
}

func TestDeleteUserSessionsBeforeVersionKeepsCurrentAndFutureGenerations(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	userID := "user-versions"
	for sessionID, version := range map[string]int64{
		"old": 1, "current": 2, "future": 3, "missing-version": 0,
	} {
		if err := store.SaveSession(ctx, sessionID, &SessionData{
			UserID: userID, Username: "alice", AuthVersion: 7, SessionVersion: version,
		}, time.Hour); err != nil {
			t.Fatalf("save %s session: %v", sessionID, err)
		}
	}
	userKey := digest(userID)
	malformedKey := secretKey(sessionPrefix, "malformed")
	if err := store.rdb.Set(ctx, malformedKey, "{", time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	if err := store.rdb.SAdd(ctx, userSessionsPrefix+userKey, malformedKey).Err(); err != nil {
		t.Fatal(err)
	}
	if err := store.rdb.ZAdd(ctx, allSessionsKey, redis.Z{Score: float64(time.Now().Add(time.Hour).UnixMilli()), Member: malformedKey}).Err(); err != nil {
		t.Fatal(err)
	}

	deleted, err := store.DeleteUserSessionsBeforeVersion(ctx, userID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 3 {
		t.Fatalf("deleted sessions = %d, want 3", deleted)
	}
	for _, sessionID := range []string{"old", "missing-version", "malformed"} {
		if _, err := store.GetSession(ctx, sessionID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("stale session %q remained: %v", sessionID, err)
		}
	}
	for _, sessionID := range []string{"current", "future"} {
		if _, err := store.GetSession(ctx, sessionID); err != nil {
			t.Fatalf("session %q was removed: %v", sessionID, err)
		}
	}
}

func TestSecurityGenerationCleanupPreservesNewSessionsAndRefreshFamilies(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	const userID = "generation-cleanup-user"
	for sessionID, versions := range map[string][2]int64{
		"old-auth": {1, 2}, "old-session": {2, 1}, "current": {2, 2}, "future": {3, 3},
	} {
		if err := store.SaveSession(ctx, sessionID, &SessionData{
			UserID: userID, Username: "alice", AuthVersion: versions[0], SessionVersion: versions[1],
		}, time.Hour); err != nil {
			t.Fatalf("save session %s: %v", sessionID, err)
		}
	}
	deleted, err := store.DeleteUserSessionsBeforeSecurityVersion(ctx, userID, 2, 2)
	if err != nil || deleted != 2 {
		t.Fatalf("generation session cleanup deleted=%d err=%v", deleted, err)
	}
	for _, sessionID := range []string{"old-auth", "old-session"} {
		if _, err := store.GetSession(ctx, sessionID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("stale session %s remained: %v", sessionID, err)
		}
	}
	for _, sessionID := range []string{"current", "future"} {
		if _, err := store.GetSession(ctx, sessionID); err != nil {
			t.Fatalf("new session %s was removed: %v", sessionID, err)
		}
	}

	refreshes := map[string]*TokenData{
		"old-refresh":     {ClientID: "client", UserID: userID, AuthVersion: 1},
		"current-refresh": {ClientID: "client", UserID: userID, AuthVersion: 2},
		"future-refresh":  {ClientID: "client", UserID: userID, AuthVersion: 3},
	}
	for token, data := range refreshes {
		if err := store.SaveRefreshToken(ctx, token, data, time.Hour); err != nil {
			t.Fatalf("save %s: %v", token, err)
		}
		if err := store.SaveTokenForRefreshFamily(ctx, token+"-access", &TokenData{
			ClientID: "client", UserID: userID, TokenUse: "access", AuthVersion: data.AuthVersion,
		}, data.FamilyKey, time.Hour); err != nil {
			t.Fatalf("save %s access token: %v", token, err)
		}
	}
	revoked, err := store.RevokeRefreshFamiliesBeforeAuthVersion(ctx, userID, 2, time.Hour)
	if err != nil || revoked != 1 {
		t.Fatalf("generation refresh cleanup revoked=%d err=%v", revoked, err)
	}
	if _, err := store.GetRefreshToken(ctx, "old-refresh"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale refresh family remained: %v", err)
	}
	for _, token := range []string{"current-refresh", "future-refresh"} {
		if _, err := store.GetRefreshToken(ctx, token); err != nil {
			t.Fatalf("new refresh family %s was removed: %v", token, err)
		}
		if _, err := store.GetToken(ctx, token+"-access"); err != nil {
			t.Fatalf("new access metadata %s was removed: %v", token, err)
		}
	}
}

func TestTouchSessionUpdatesLastSeenWithoutChangingTTL(t *testing.T) {
	store, mini := testStore(t)
	ctx := context.Background()
	data := &SessionData{UserID: "user-1", Username: "alice", AuthVersion: 1}
	if err := store.SaveSession(ctx, "cookie", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	key := secretKey(sessionPrefix, "cookie")
	before := mini.TTL(key)
	seenAt := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	if err := store.TouchSession(ctx, "cookie", seenAt); err != nil {
		t.Fatal(err)
	}
	updated, err := store.GetSession(ctx, "cookie")
	if err != nil {
		t.Fatal(err)
	}
	if !updated.LastSeenAt.Equal(seenAt) {
		t.Fatalf("last seen = %s, want %s", updated.LastSeenAt, seenAt)
	}
	if after := mini.TTL(key); after != before {
		t.Fatalf("session TTL changed from %s to %s", before, after)
	}
}

func TestActiveSessionCounterDoesNotScanKeys(t *testing.T) {
	store, mini := testStore(t)
	ctx := context.Background()
	baseTime := time.Now().UTC()
	mini.SetTime(baseTime)
	first := &SessionData{UserID: "user-1", Username: "alice", AuthVersion: 1}
	second := &SessionData{UserID: "user-2", Username: "bob", AuthVersion: 1}
	if err := store.SaveSession(ctx, "cookie-a", first, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSession(ctx, "cookie-b", second, time.Minute); err != nil {
		t.Fatal(err)
	}
	if count, err := store.CountActiveSessions(ctx); err != nil || count != 2 {
		t.Fatalf("active sessions = %d, err=%v", count, err)
	}
	if err := store.DeleteSession(ctx, "cookie-a"); err != nil {
		t.Fatal(err)
	}
	if count, err := store.CountActiveSessions(ctx); err != nil || count != 1 {
		t.Fatalf("active sessions after revoke = %d, err=%v", count, err)
	}
	mini.FastForward(2 * time.Minute)
	mini.SetTime(baseTime.Add(2 * time.Minute))
	if count, err := store.CountActiveSessions(ctx); err != nil || count != 0 {
		t.Fatalf("active sessions after expiry = %d, err=%v", count, err)
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
	mismatch.RecordVersion = "stale-record-version"
	if _, err := store.ConsumeAuthorizationCodeIfMatch(ctx, "code", &mismatch, time.Minute); !errors.Is(err, ErrValueMismatch) {
		t.Fatalf("mismatch error = %v", err)
	}
	if _, err := store.GetAuthorizationCode(ctx, "code"); err != nil {
		t.Fatalf("mismatch consumed code: %v", err)
	}
	if _, err := store.ConsumeAuthorizationCodeIfMatch(ctx, "code", data, time.Minute); err != nil {
		t.Fatal(err)
	}
	used, err := store.GetAuthorizationCode(ctx, "code")
	if !errors.Is(err, ErrAuthorizationCodeReuse) || used.RecordVersion != data.RecordVersion {
		t.Fatalf("used code marker = %#v, err=%v", used, err)
	}
	if _, err := store.ConsumeAuthorizationCodeIfMatch(ctx, "code", data, time.Minute); !errors.Is(err, ErrAuthorizationCodeReuse) {
		t.Fatalf("authorization code reuse error = %v", err)
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

func TestRotateRefreshTokenAndStoreAccessCommitsAndRevokesAsOneFamily(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	data := &TokenData{
		ClientID: "client", UserID: "user", Scopes: []string{"offline_access"},
		AuthVersion: 3, AuthorizationIssuedAt: 42,
	}
	if err := store.SaveRefreshToken(ctx, "old-refresh", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	access := &TokenData{
		ClientID: data.ClientID, UserID: data.UserID, Scopes: data.Scopes,
		AuthVersion: data.AuthVersion, AuthorizationIssuedAt: data.AuthorizationIssuedAt,
	}
	if _, err := store.RotateRefreshTokenAndStoreAccess(
		ctx, "old-refresh", "new-refresh", "new-access", data, access, time.Hour, time.Minute,
	); err != nil {
		t.Fatalf("rotate refresh and access metadata: %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, "new-refresh"); err != nil {
		t.Fatalf("new refresh token was not committed: %v", err)
	}
	storedAccess, err := store.GetToken(ctx, "new-access")
	if err != nil {
		t.Fatalf("new access metadata was not committed: %v", err)
	}
	if storedAccess.TokenUse != "access" || storedAccess.FamilyKey != data.FamilyKey {
		t.Fatalf("new access metadata is not family-bound: %#v", storedAccess)
	}
	indexed, err := store.rdb.SIsMember(ctx, userRefreshFamiliesPrefix+digest(data.UserID), data.FamilyKey).Result()
	if err != nil || !indexed {
		t.Fatalf("rotated family is not indexed for user revocation: indexed=%v err=%v", indexed, err)
	}

	replayAccess := &TokenData{
		ClientID: data.ClientID, UserID: data.UserID, Scopes: data.Scopes,
		AuthVersion: data.AuthVersion, AuthorizationIssuedAt: data.AuthorizationIssuedAt,
	}
	if _, err := store.RotateRefreshTokenAndStoreAccess(
		ctx, "old-refresh", "replay-refresh", "replay-access", data, replayAccess, time.Hour, time.Minute,
	); !errors.Is(err, ErrRefreshTokenReuse) {
		t.Fatalf("old refresh replay error = %v, want ErrRefreshTokenReuse", err)
	}
	if _, err := store.GetRefreshToken(ctx, "new-refresh"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("new refresh survived family reuse: %v", err)
	}
	if _, err := store.GetToken(ctx, "new-access"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("new access metadata survived family reuse: %v", err)
	}
	indexed, err = store.rdb.SIsMember(ctx, userRefreshFamiliesPrefix+digest(data.UserID), data.FamilyKey).Result()
	if err != nil || indexed {
		t.Fatalf("revoked family remained in user index: indexed=%v err=%v", indexed, err)
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
	indexed, err := store.rdb.SIsMember(ctx, userRefreshFamiliesPrefix+digest(data.UserID), data.FamilyKey).Result()
	if err != nil || indexed {
		t.Fatalf("revoked family remained in user index: indexed=%v err=%v", indexed, err)
	}
	if exists, err := store.rdb.Exists(ctx, userRefreshFamiliesPrefix+digest(data.UserID)).Result(); err != nil || exists != 0 {
		t.Fatalf("empty user family index was not removed: exists=%d err=%v", exists, err)
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

func TestRevokeRefreshFamiliesForUserIsAtomicAndUserScoped(t *testing.T) {
	store, mini := testStore(t)
	ctx := context.Background()
	userID := "sensitive-user-a"
	otherUserID := "sensitive-user-b"

	first := &TokenData{ClientID: "client-a", UserID: userID, Scopes: []string{"offline_access"}, AuthVersion: 1}
	second := &TokenData{ClientID: "client-b", UserID: userID, Scopes: []string{"offline_access"}, AuthVersion: 1}
	other := &TokenData{ClientID: "client-c", UserID: otherUserID, Scopes: []string{"offline_access"}, AuthVersion: 1}
	for token, data := range map[string]*TokenData{"refresh-a": first, "refresh-b": second, "refresh-other": other} {
		if err := store.SaveRefreshToken(ctx, token, data, time.Hour); err != nil {
			t.Fatalf("save %s: %v", token, err)
		}
	}
	if err := store.SaveTokenForRefreshFamily(ctx, "access-a", &TokenData{ClientID: "client-a", UserID: userID, TokenUse: "access"}, first.FamilyKey, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTokenForRefreshFamily(ctx, "access-b", &TokenData{ClientID: "client-b", UserID: userID, TokenUse: "access"}, second.FamilyKey, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTokenForRefreshFamily(ctx, "access-other", &TokenData{ClientID: "client-c", UserID: otherUserID, TokenUse: "access"}, other.FamilyKey, time.Hour); err != nil {
		t.Fatal(err)
	}

	revoked, err := store.RevokeRefreshFamiliesForUser(ctx, userID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if revoked != 2 {
		t.Fatalf("revoked families = %d, want 2", revoked)
	}
	for _, token := range []string{"refresh-a", "refresh-b"} {
		if _, err := store.GetRefreshToken(ctx, token); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s remained available: %v", token, err)
		}
	}
	for _, tokenID := range []string{"access-a", "access-b"} {
		if _, err := store.GetToken(ctx, tokenID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s remained available: %v", tokenID, err)
		}
	}
	if _, err := store.GetRefreshToken(ctx, "refresh-other"); err != nil {
		t.Fatalf("other user's refresh token was removed: %v", err)
	}
	if _, err := store.GetToken(ctx, "access-other"); err != nil {
		t.Fatalf("other user's access metadata was removed: %v", err)
	}
	if err := store.SaveTokenForRefreshFamily(ctx, "resurrected-access", &TokenData{ClientID: "client-a", UserID: userID, TokenUse: "access"}, first.FamilyKey, time.Hour); !errors.Is(err, ErrRefreshFamilyRevoked) {
		t.Fatalf("revoked family accepted new metadata: %v", err)
	}
	for _, key := range mini.Keys() {
		if strings.Contains(key, userID) || strings.Contains(key, otherUserID) {
			t.Fatalf("user identifier leaked into Redis key %q", key)
		}
	}
}

func TestUserClientAuthorizationRevocationUsesOpaqueKeyAndOrderedTime(t *testing.T) {
	store, mini := testStore(t)
	ctx := context.Background()
	baseTime := time.Date(2026, 7, 26, 9, 0, 0, 0, time.UTC)
	mini.SetTime(baseTime)
	userID := "sensitive-user-id"
	clientID := "sensitive-client-id"

	issuedAt, err := store.AuthorizationIssueTime(ctx, userID, clientID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	revokedAt, err := store.RevokeUserClientAuthorization(ctx, userID, clientID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if revokedAt <= issuedAt {
		t.Fatalf("revocation time %d did not advance past issue time %d", revokedAt, issuedAt)
	}
	for _, key := range mini.Keys() {
		if strings.Contains(key, userID) || strings.Contains(key, clientID) {
			t.Fatalf("authorization identifiers leaked into Redis key %q", key)
		}
	}
	key := authorizationRevocationKey(userID, clientID)
	if ttl := mini.TTL(key); ttl != time.Hour {
		t.Fatalf("revocation marker TTL = %v, want %v", ttl, time.Hour)
	}
	if ttl := mini.TTL(authorizationClockKey(userID, clientID)); ttl != time.Hour {
		t.Fatalf("authorization clock TTL = %v, want %v", ttl, time.Hour)
	}

	for _, test := range []struct {
		name     string
		issuedAt int64
		want     bool
	}{
		{name: "before", issuedAt: revokedAt - 1, want: true},
		{name: "same instant", issuedAt: revokedAt, want: true},
		{name: "after", issuedAt: revokedAt + 1, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, checkErr := store.IsUserClientAuthorizationRevoked(ctx, userID, clientID, test.issuedAt)
			if checkErr != nil {
				t.Fatal(checkErr)
			}
			if got != test.want {
				t.Fatalf("revoked = %v, want %v", got, test.want)
			}
		})
	}

	mini.SetTime(baseTime.Add(-time.Hour))
	reissuedAt, err := store.AuthorizationIssueTime(ctx, userID, clientID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if reissuedAt <= revokedAt {
		t.Fatalf("reissued authorization time %d did not advance past marker %d", reissuedAt, revokedAt)
	}
	secondRevocation, err := store.RevokeUserClientAuthorization(ctx, userID, clientID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if secondRevocation <= reissuedAt {
		t.Fatalf("second revocation time %d did not advance past reissue %d", secondRevocation, reissuedAt)
	}
	revoked, err := store.IsUserClientAuthorizationRevoked(ctx, userID, clientID, reissuedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("second revocation did not invalidate the reissued authorization")
	}
}
