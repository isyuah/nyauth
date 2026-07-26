package database_test

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nyasharp/nyauth/internal/auth"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestJWKEncryptedPrivateKeyRoundTripAndRotationLifecycle(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	const (
		rotation        = 24 * time.Hour
		maximumTokenTTL = 2 * time.Hour
		clockSkew       = 2 * time.Minute
	)

	first := auth.NewJWKManager(schema.pool, 2048, rotation)
	second := auth.NewJWKManager(schema.pool, 2048, rotation)
	for index, manager := range []*auth.JWKManager{first, second} {
		if err := manager.Configure(masterKey, maximumTokenTTL); err != nil {
			t.Fatalf("configure JWK manager %d: %v", index, err)
		}
	}

	start := make(chan struct{})
	errorsByInstance := make(chan error, 2)
	var instances sync.WaitGroup
	for _, manager := range []*auth.JWKManager{first, second} {
		instances.Add(1)
		go func(manager *auth.JWKManager) {
			defer instances.Done()
			<-start
			errorsByInstance <- manager.EnsureActiveKey(ctx)
		}(manager)
	}
	close(start)
	instances.Wait()
	close(errorsByInstance)
	for err := range errorsByInstance {
		if err != nil {
			t.Fatalf("concurrent EnsureActiveKey: %v", err)
		}
	}

	var totalKeys, signingKeys int
	if err := schema.pool.QueryRow(ctx, `
		SELECT COUNT(*),COUNT(*) FILTER (WHERE status='signing') FROM jwk_keys
	`).Scan(&totalKeys, &signingKeys); err != nil {
		t.Fatalf("count initial JWK rows: %v", err)
	}
	if totalKeys != 1 || signingKeys != 1 {
		t.Fatalf("concurrent initialization stored total=%d signing=%d keys, want 1/1", totalKeys, signingKeys)
	}

	active, err := first.GetActiveKey(ctx)
	if err != nil {
		t.Fatalf("get active JWK: %v", err)
	}
	if active.EncryptedPrivateKey == nil || !strings.HasPrefix(*active.EncryptedPrivateKey, "v1:primary:") {
		t.Fatalf("active JWK does not use the expected envelope: %#v", active.EncryptedPrivateKey)
	}
	if strings.Contains(*active.EncryptedPrivateKey, "PRIVATE KEY") {
		t.Fatal("persisted JWK envelope contains plaintext private-key material")
	}

	privateFromFirst, firstKID, err := first.GetPrivateKey(ctx)
	if err != nil {
		t.Fatalf("decrypt private JWK with first manager: %v", err)
	}
	privateFromSecond, secondKID, err := second.GetPrivateKey(ctx)
	if err != nil {
		t.Fatalf("decrypt private JWK after database round trip: %v", err)
	}
	if firstKID != active.Kid || secondKID != active.Kid || privateFromFirst.N.Cmp(privateFromSecond.N) != 0 || privateFromFirst.D.Cmp(privateFromSecond.D) != 0 {
		t.Fatal("JWK private key changed across manager/database round trip")
	}
	assertJWKPublicKeyMatchesPrivate(t, active.PublicKey, privateFromFirst)

	wrongKeyManager := auth.NewJWKManager(schema.pool, 2048, rotation)
	if err := wrongKeyManager.Configure(bytes.Repeat([]byte{0x5a}, 32), maximumTokenTTL); err != nil {
		t.Fatalf("configure wrong-key JWK manager: %v", err)
	}
	if _, _, err := wrongKeyManager.GetPrivateKey(ctx); err == nil {
		t.Fatal("JWK private key decrypted with a different master key")
	}

	rotationStarted := time.Now().UTC()
	rotated, err := first.GenerateKey(ctx)
	rotationFinished := time.Now().UTC()
	if err != nil {
		t.Fatalf("force JWK rotation: %v", err)
	}
	if rotated.Kid == active.Kid || rotated.Status != models.JWKStatusSigning || rotated.EncryptedPrivateKey == nil {
		t.Fatalf("unexpected rotated signing JWK: %#v", rotated)
	}
	if *rotated.EncryptedPrivateKey == *active.EncryptedPrivateKey {
		t.Fatal("JWK rotation reused the previous encrypted private key")
	}

	var oldStatus models.JWKStatus
	var oldHasPrivateKey bool
	var oldVerifyUntil time.Time
	if err := schema.pool.QueryRow(ctx, `
		SELECT status,encrypted_private_key IS NOT NULL,verify_until FROM jwk_keys WHERE kid=$1
	`, active.Kid).Scan(&oldStatus, &oldHasPrivateKey, &oldVerifyUntil); err != nil {
		t.Fatalf("read verification JWK: %v", err)
	}
	if oldStatus != models.JWKStatusVerification || oldHasPrivateKey {
		t.Fatalf("old JWK lifecycle status=%q private=%v, want verification/false", oldStatus, oldHasPrivateKey)
	}
	expectedRetention := maximumTokenTTL + clockSkew
	if oldVerifyUntil.Before(rotationStarted.Add(expectedRetention-time.Second)) || oldVerifyUntil.After(rotationFinished.Add(expectedRetention+time.Second)) {
		t.Fatalf("old JWK verify_until=%s, want rotation time + %s", oldVerifyUntil, expectedRetention)
	}

	publicKeys, err := second.ListActivePublicKeys(ctx)
	if err != nil {
		t.Fatalf("list signing and verification JWKs: %v", err)
	}
	statuses := make(map[string]models.JWKStatus, len(publicKeys))
	for _, key := range publicKeys {
		statuses[key.Kid] = key.Status
	}
	if statuses[active.Kid] != models.JWKStatusVerification || statuses[rotated.Kid] != models.JWKStatusSigning || len(statuses) != 2 {
		t.Fatalf("unexpected public JWK set after rotation: %#v", statuses)
	}

	rotatedPrivate, rotatedKID, err := second.GetPrivateKey(ctx)
	if err != nil {
		t.Fatalf("decrypt rotated JWK from second manager: %v", err)
	}
	if rotatedKID != rotated.Kid || rotatedPrivate.N.Cmp(privateFromFirst.N) == 0 {
		t.Fatal("second manager did not observe the new signing key")
	}
	assertJWKPublicKeyMatchesPrivate(t, rotated.PublicKey, rotatedPrivate)

	if _, err := schema.pool.Exec(ctx, `
		UPDATE jwk_keys
		SET signing_started_at=NOW()-INTERVAL '1 hour',verify_until=NOW()-INTERVAL '1 second'
		WHERE kid=$1
	`, active.Kid); err != nil {
		t.Fatalf("expire verification JWK: %v", err)
	}
	if err := second.RotateKeys(ctx); err != nil {
		t.Fatalf("retire expired verification JWK: %v", err)
	}
	if err := schema.pool.QueryRow(ctx, `
		SELECT status,encrypted_private_key IS NOT NULL FROM jwk_keys WHERE kid=$1
	`, active.Kid).Scan(&oldStatus, &oldHasPrivateKey); err != nil {
		t.Fatalf("read retired JWK: %v", err)
	}
	if oldStatus != models.JWKStatusRetired || oldHasPrivateKey {
		t.Fatalf("expired JWK lifecycle status=%q private=%v, want retired/false", oldStatus, oldHasPrivateKey)
	}
	publicKeys, err = first.ListActivePublicKeys(ctx)
	if err != nil {
		t.Fatalf("list JWKs after retirement: %v", err)
	}
	if len(publicKeys) != 1 || publicKeys[0].Kid != rotated.Kid || publicKeys[0].Status != models.JWKStatusSigning {
		t.Fatalf("retired key remained in JWKS: %#v", publicKeys)
	}
}

func assertJWKPublicKeyMatchesPrivate(t *testing.T, publicPEM string, privateKey *rsa.PrivateKey) {
	t.Helper()
	block, trailing := pem.Decode([]byte(publicPEM))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(trailing)) != 0 {
		t.Fatal("stored JWK public key is not a single PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse stored JWK public key: %v", err)
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok || publicKey.N.Cmp(privateKey.N) != 0 || publicKey.E != privateKey.E {
		t.Fatal("stored JWK public key does not match decrypted private key")
	}
}
