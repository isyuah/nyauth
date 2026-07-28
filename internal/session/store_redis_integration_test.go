package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisIntegrationTimeout = 10 * time.Second

type redisIntegrationStores struct {
	first         *Store
	second        *Store
	cleanupClient *redis.Client
}

func newRedisIntegrationStores(t *testing.T) redisIntegrationStores {
	t.Helper()

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

	options := &redis.Options{
		Addr:     addr,
		Username: os.Getenv("NYAUTH_TEST_REDIS_USERNAME"),
		Password: os.Getenv("NYAUTH_TEST_REDIS_PASSWORD"),
		DB:       database,
	}
	firstOptions := *options
	secondOptions := *options
	firstClient := redis.NewClient(&firstOptions)
	secondClient := redis.NewClient(&secondOptions)
	t.Cleanup(func() {
		_ = firstClient.Close()
		_ = secondClient.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), redisIntegrationTimeout)
	defer cancel()
	if err := firstClient.Ping(ctx).Err(); err != nil {
		t.Fatalf("connect to integration Redis with first client: %v", err)
	}
	if err := secondClient.Ping(ctx).Err(); err != nil {
		t.Fatalf("connect to integration Redis with second client: %v", err)
	}

	return redisIntegrationStores{
		first:         NewStore(firstClient),
		second:        NewStore(secondClient),
		cleanupClient: firstClient,
	}
}

func redisIntegrationID(t *testing.T) string {
	t.Helper()
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatalf("generate Redis integration test identifier: %v", err)
	}
	return hex.EncodeToString(value[:])
}

func cleanupRedisIntegrationKeys(t *testing.T, client *redis.Client, keys ...string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), redisIntegrationTimeout)
		defer cancel()
		if err := client.Del(ctx, keys...).Err(); err != nil {
			t.Errorf("remove Redis integration test keys: %v", err)
		}
	})
}

func TestRedisIntegrationAuthorizationCodeConsumedOnceAcrossStores(t *testing.T) {
	stores := newRedisIntegrationStores(t)
	ctx, cancel := context.WithTimeout(context.Background(), redisIntegrationTimeout)
	defer cancel()

	id := redisIntegrationID(t)
	code := "integration-code-" + id
	data := &AuthorizationData{
		ClientID:        "integration-client-" + id,
		UserID:          "integration-user-" + id,
		RedirectURI:     "https://client.invalid/callback/" + id,
		Scopes:          []string{"openid", "profile"},
		CodeChallenge:   "integration-challenge-" + id,
		ChallengeMethod: "S256",
		Nonce:           "integration-nonce-" + id,
		AuthVersion:     7,
	}
	cleanupRedisIntegrationKeys(t, stores.cleanupClient, secretKey(codePrefix, code), secretKey(codeUsedPrefix, code))
	if err := stores.first.SaveAuthorizationCode(ctx, code, data, time.Minute); err != nil {
		t.Fatalf("save authorization code: %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, store := range []*Store{stores.first, stores.second} {
		workers.Add(1)
		go func(candidate *Store) {
			defer workers.Done()
			<-start
			_, err := candidate.ConsumeAuthorizationCodeIfMatch(ctx, code, data, time.Minute)
			results <- err
		}(store)
	}
	close(start)
	workers.Wait()
	close(results)

	successes := 0
	reuses := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrAuthorizationCodeReuse):
			reuses++
		default:
			t.Fatalf("unexpected authorization code consumption result: %v", err)
		}
	}
	if successes != 1 || reuses != 1 {
		t.Fatalf("authorization code outcomes: successes=%d reuses=%d, want 1 and 1", successes, reuses)
	}
	if _, err := stores.first.GetAuthorizationCode(ctx, code); !errors.Is(err, ErrAuthorizationCodeReuse) {
		t.Fatalf("used authorization code state through first store: %v", err)
	}
	if _, err := stores.second.GetAuthorizationCode(ctx, code); !errors.Is(err, ErrAuthorizationCodeReuse) {
		t.Fatalf("used authorization code state through second store: %v", err)
	}
}

func TestRedisIntegrationRefreshReuseRevokesFamilyAcrossStores(t *testing.T) {
	stores := newRedisIntegrationStores(t)
	ctx, cancel := context.WithTimeout(context.Background(), redisIntegrationTimeout)
	defer cancel()

	id := redisIntegrationID(t)
	oldToken := "integration-refresh-old-" + id
	newTokens := []string{"integration-refresh-new-a-" + id, "integration-refresh-new-b-" + id}
	familyID := "integration-family-" + id
	familyKey := digest(familyID)
	data := &TokenData{
		ClientID:    "integration-client-" + id,
		UserID:      "integration-user-" + id,
		Scopes:      []string{"openid", "offline_access"},
		TokenUse:    "refresh",
		AuthVersion: 11,
		FamilyID:    familyID,
		FamilyKey:   familyKey,
	}
	cleanupRedisIntegrationKeys(t, stores.cleanupClient,
		secretKey(refreshPrefix, oldToken),
		refreshUsedPrefix+digest(oldToken),
		secretKey(refreshPrefix, newTokens[0]),
		secretKey(refreshPrefix, newTokens[1]),
		refreshFamilyPrefix+familyKey,
		refreshRevokedPrefix+familyKey,
		userRefreshFamiliesPrefix+digest(data.UserID),
		secretKey(tokenPrefix, "integration-access-probe-"+id),
	)
	if err := stores.first.SaveRefreshToken(ctx, oldToken, data, time.Hour); err != nil {
		t.Fatalf("save refresh token: %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for index, store := range []*Store{stores.first, stores.second} {
		workers.Add(1)
		go func(candidate *Store, replacement string) {
			defer workers.Done()
			<-start
			_, err := candidate.RotateRefreshToken(ctx, oldToken, replacement, data, time.Hour)
			results <- err
		}(store, newTokens[index])
	}
	close(start)
	workers.Wait()
	close(results)

	successes := 0
	reuses := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrRefreshTokenReuse):
			reuses++
		default:
			t.Fatalf("unexpected refresh rotation result: %v", err)
		}
	}
	if successes != 1 || reuses != 1 {
		t.Fatalf("refresh rotation outcomes: successes=%d reuse=%d, want 1 and 1", successes, reuses)
	}
	for _, token := range append([]string{oldToken}, newTokens...) {
		if _, err := stores.first.GetRefreshToken(ctx, token); !errors.Is(err, ErrNotFound) {
			t.Fatalf("revoked refresh family token %q visible through first store: %v", token, err)
		}
		if _, err := stores.second.GetRefreshToken(ctx, token); !errors.Is(err, ErrNotFound) {
			t.Fatalf("revoked refresh family token %q visible through second store: %v", token, err)
		}
	}
	probe := &TokenData{ClientID: data.ClientID, UserID: data.UserID, TokenUse: "access", AuthVersion: data.AuthVersion}
	if err := stores.second.SaveTokenForRefreshFamily(ctx, "integration-access-probe-"+id, probe, familyKey, time.Minute); !errors.Is(err, ErrRefreshFamilyRevoked) {
		t.Fatalf("revoked refresh family accepted new token metadata: %v", err)
	}
}

func TestRedisIntegrationSessionAuthStateAndRevocationAreShared(t *testing.T) {
	stores := newRedisIntegrationStores(t)
	ctx, cancel := context.WithTimeout(context.Background(), redisIntegrationTimeout)
	defer cancel()

	id := redisIntegrationID(t)
	sessionID := "integration-session-" + id
	userID := "integration-user-" + id
	sessionKey := secretKey(sessionPrefix, sessionID)
	userSessionsKey := userSessionsPrefix + digest(userID)
	cleanupRedisIntegrationKeys(t, stores.cleanupClient, sessionKey, userSessionsKey)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), redisIntegrationTimeout)
		defer cleanupCancel()
		if err := stores.cleanupClient.ZRem(cleanupCtx, allSessionsKey, sessionKey).Err(); err != nil {
			t.Errorf("remove Redis integration session index member: %v", err)
		}
	})

	data := &SessionData{
		PublicID:    "integration-public-" + id,
		UserID:      userID,
		Username:    "integration-user",
		AuthVersion: 23,
		CSRFToken:   "integration-csrf-" + id,
	}
	if err := stores.first.SaveSession(ctx, sessionID, data, time.Hour); err != nil {
		t.Fatalf("save session through first store: %v", err)
	}
	observed, err := stores.second.GetSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("read session through second store: %v", err)
	}
	if observed.AuthVersion != data.AuthVersion || observed.UserID != userID {
		t.Fatalf("shared session auth state = {user_id:%q auth_version:%d}, want {%q %d}", observed.UserID, observed.AuthVersion, userID, data.AuthVersion)
	}

	observed.AuthVersion++
	if err := stores.second.SaveSession(ctx, sessionID, observed, time.Hour); err != nil {
		t.Fatalf("update session auth state through second store: %v", err)
	}
	updated, err := stores.first.GetSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("read updated session auth state through first store: %v", err)
	}
	if updated.AuthVersion != data.AuthVersion+1 {
		t.Fatalf("updated shared auth_version = %d, want %d", updated.AuthVersion, data.AuthVersion+1)
	}

	if err := stores.second.DeleteSession(ctx, sessionID); err != nil {
		t.Fatalf("revoke session through second store: %v", err)
	}
	if _, err := stores.first.GetSession(ctx, sessionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked session remained visible through first store: %v", err)
	}
}

func TestRedisIntegrationSessionGenerationCleanupIsShared(t *testing.T) {
	stores := newRedisIntegrationStores(t)
	ctx, cancel := context.WithTimeout(context.Background(), redisIntegrationTimeout)
	defer cancel()

	id := redisIntegrationID(t)
	userID := "integration-generation-user-" + id
	userSessionsKey := userSessionsPrefix + digest(userID)
	sessionIDs := []string{
		"integration-generation-old-" + id,
		"integration-generation-current-" + id,
		"integration-generation-future-" + id,
	}
	sessionKeys := make([]string, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		sessionKeys = append(sessionKeys, secretKey(sessionPrefix, sessionID))
	}
	cleanupRedisIntegrationKeys(t, stores.cleanupClient, append(sessionKeys, userSessionsKey)...)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), redisIntegrationTimeout)
		defer cleanupCancel()
		members := make([]interface{}, 0, len(sessionKeys))
		for _, key := range sessionKeys {
			members = append(members, key)
		}
		if err := stores.cleanupClient.ZRem(cleanupCtx, allSessionsKey, members...).Err(); err != nil {
			t.Errorf("remove Redis generation session index members: %v", err)
		}
	})

	for index, version := range []int64{4, 5, 6} {
		if err := stores.first.SaveSession(ctx, sessionIDs[index], &SessionData{
			UserID: userID, Username: "integration-user", AuthVersion: 9, SessionVersion: version,
		}, time.Hour); err != nil {
			t.Fatalf("save generation %d session: %v", version, err)
		}
	}
	deleted, err := stores.second.DeleteUserSessionsBeforeVersion(ctx, userID, 5)
	if err != nil {
		t.Fatalf("delete stale generations through second store: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted sessions = %d, want 1", deleted)
	}
	if _, err := stores.first.GetSession(ctx, sessionIDs[0]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale session remained visible through first store: %v", err)
	}
	for _, sessionID := range sessionIDs[1:] {
		if _, err := stores.first.GetSession(ctx, sessionID); err != nil {
			t.Fatalf("current or future session %q was removed: %v", sessionID, err)
		}
	}
}
