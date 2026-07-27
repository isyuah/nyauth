package database_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/mfa"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

const (
	passkeyTestRPID   = "auth.example.test"
	passkeyTestOrigin = "https://auth.example.test"
	passkeyTestKeyID  = "primary"
)

var passkeyTestMasterKey = []byte("0123456789abcdef0123456789abcdef")

func TestPasskeyRegistrationEncryptsAndAuthenticatesStoredCredential(t *testing.T) {
	schema := newPasskeyTestSchema(t)
	ctx := context.Background()
	service := newPasskeyTestService(t, schema, passkeyTestRPID)
	current := registrationTestUser("passkey-envelope", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, current)

	options, err := service.BeginPasskeyRegistration(ctx, current)
	if err != nil {
		t.Fatalf("begin Passkey registration: %v", err)
	}
	parsed, credentialID, publicKey, _ := passkeyRegistrationResponse(t, options, passkeyTestRPID, passkeyTestOrigin)
	registered, err := service.FinishPasskeyRegistration(
		ctx, current,
		mfa.AuthenticationBinding{AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion},
		"Windows Hello", options.Session, parsed,
		mfa.ChallengeCommitGate{
			AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
			Consume: func(context.Context) error { return nil },
		},
		mfa.AuditContext{ActorID: current.ID, ActorName: current.Username}, time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("finish Passkey registration: %v", err)
	}

	var rowID uuid.UUID
	var storedRPID string
	var storedUserID uuid.UUID
	var storedCredentialID []byte
	var ciphertext string
	if err := schema.pool.QueryRow(ctx, `
		SELECT id,rp_id,user_id,credential_id,credential_ciphertext
		FROM user_passkey_credentials WHERE id=$1
	`, registered.ID).Scan(&rowID, &storedRPID, &storedUserID, &storedCredentialID, &ciphertext); err != nil {
		t.Fatalf("load stored Passkey: %v", err)
	}
	if !bytes.Equal(storedCredentialID, credentialID) {
		t.Fatalf("stored credential ID=%x want=%x", storedCredentialID, credentialID)
	}
	if strings.Contains(ciphertext, base64.RawURLEncoding.EncodeToString(publicKey)) {
		t.Fatal("Passkey envelope contains the encoded credential public key")
	}
	plaintext, err := crypto.DecryptEnvelope(
		map[string][]byte{passkeyTestKeyID: passkeyTestMasterKey},
		"mfa.passkey.credential", ciphertext,
		passkeyTestAAD(storedRPID, rowID, storedUserID, storedCredentialID),
	)
	if err != nil {
		t.Fatalf("decrypt stored Passkey envelope: %v", err)
	}
	var stored gowebauthn.Credential
	remainder, err := stored.UnmarshalMsg(plaintext)
	if err != nil || len(remainder) != 0 {
		t.Fatalf("decode stored credential: remainder=%d err=%v", len(remainder), err)
	}
	if !bytes.Equal(stored.ID, credentialID) || !bytes.Equal(stored.PublicKey, publicKey) {
		t.Fatalf("stored credential does not match registration: id=%x key=%x", stored.ID, stored.PublicKey)
	}
	if verified, err := service.VerifyStoredPasskeys(ctx); err != nil || verified != 1 {
		t.Fatalf("VerifyStoredPasskeys()=%d err=%v", verified, err)
	}
	updated, err := user.NewService(user.NewStore(schema.pool)).GetByID(ctx, current.ID)
	if err != nil || updated.AuthVersion != current.AuthVersion+1 {
		t.Fatalf("user after Passkey registration=%#v err=%v", updated, err)
	}

	tamperedCredentialID := append([]byte(nil), storedCredentialID...)
	tamperedCredentialID[0] ^= 0xff
	if _, err := schema.pool.Exec(ctx, `
		UPDATE user_passkey_credentials SET credential_id=$2 WHERE id=$1
	`, rowID, tamperedCredentialID); err != nil {
		t.Fatalf("tamper credential ID: %v", err)
	}
	if _, err := service.VerifyStoredPasskeys(ctx); err == nil || !strings.Contains(err.Error(), "verifying stored Passkey envelope") {
		t.Fatalf("VerifyStoredPasskeys accepted AAD-bound credential ID tampering: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `
		UPDATE user_passkey_credentials SET credential_id=$2 WHERE id=$1
	`, rowID, storedCredentialID); err != nil {
		t.Fatalf("restore credential ID: %v", err)
	}

	tamperedCiphertext := tamperPasskeyEnvelope(t, ciphertext)
	if _, err := schema.pool.Exec(ctx, `
		UPDATE user_passkey_credentials SET credential_ciphertext=$2 WHERE id=$1
	`, rowID, tamperedCiphertext); err != nil {
		t.Fatalf("tamper credential envelope: %v", err)
	}
	if _, err := service.VerifyStoredPasskeys(ctx); err == nil {
		t.Fatal("VerifyStoredPasskeys accepted modified envelope ciphertext")
	}
}

func TestPasskeyRegistrationRollsBackWhenRedisCommitGateFails(t *testing.T) {
	schema := newPasskeyTestSchema(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	service := newPasskeyTestService(t, schema, passkeyTestRPID)
	current := registrationTestUser("passkey-gate-rollback", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, current)
	options, err := service.BeginPasskeyRegistration(ctx, current)
	if err != nil {
		t.Fatalf("begin Passkey registration: %v", err)
	}
	parsed, _, _, _ := passkeyRegistrationResponse(t, options, passkeyTestRPID, passkeyTestOrigin)

	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr(), MaxRetries: 0})
	t.Cleanup(func() { _ = rdb.Close() })
	store := session.NewStore(rdb)
	const ceremonyID = "passkey-registration-gate"
	if err := store.SaveWebAuthnCeremony(ctx, ceremonyID, &session.WebAuthnCeremonyData{
		SessionData: options.Session, Purpose: "registration",
	}, 5*time.Minute); err != nil {
		t.Fatalf("save WebAuthn ceremony: %v", err)
	}
	mini.Close()

	_, err = service.FinishPasskeyRegistration(
		ctx, current,
		mfa.AuthenticationBinding{AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion},
		"Rollback key", options.Session, parsed,
		mfa.ChallengeCommitGate{
			AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
			Consume: func(ctx context.Context) error {
				_, consumeErr := store.ConsumeWebAuthnCeremony(ctx, ceremonyID)
				return consumeErr
			},
		},
		mfa.AuditContext{ActorID: current.ID, ActorName: current.Username}, time.Now().UTC(),
	)
	if err == nil || !strings.Contains(err.Error(), "consuming MFA pending challenge") {
		t.Fatalf("registration gate failure=%v", err)
	}

	var credentialCount, auditCount int
	var authVersion int64
	if err := schema.pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM user_passkey_credentials WHERE user_id=$1),
			(SELECT COUNT(*) FROM audit_event_outbox WHERE event=$2 AND aggregate_id=$3),
			(SELECT auth_version FROM users WHERE id=$1)
	`, current.ID, models.AuditPasskeyRegistered, current.ID.String()).Scan(
		&credentialCount, &auditCount, &authVersion,
	); err != nil {
		t.Fatalf("read registration rollback state: %v", err)
	}
	if credentialCount != 0 || auditCount != 0 || authVersion != current.AuthVersion {
		t.Fatalf("gate failure committed PostgreSQL state: credentials=%d audits=%d auth_version=%d", credentialCount, auditCount, authVersion)
	}
}

func TestPasskeyAssertionsVerifyAndConsumeCrossInstanceCeremony(t *testing.T) {
	schema := newPasskeyTestSchema(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	firstService := newPasskeyTestService(t, schema, passkeyTestRPID)
	secondService := newPasskeyTestService(t, schema, passkeyTestRPID)
	current := registrationTestUser("passkey-assertion", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, current)

	registration, err := firstService.BeginPasskeyRegistration(ctx, current)
	if err != nil {
		t.Fatalf("begin Passkey registration: %v", err)
	}
	creation, credentialID, _, privateKey := passkeyRegistrationResponse(
		t, registration, passkeyTestRPID, passkeyTestOrigin,
	)
	registered, err := firstService.FinishPasskeyRegistration(
		ctx, current,
		mfa.AuthenticationBinding{AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion},
		"Assertion key", registration.Session, creation,
		mfa.ChallengeCommitGate{
			AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
			Consume: func(context.Context) error { return nil },
		},
		mfa.AuditContext{ActorID: current.ID, ActorName: current.Username}, time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("finish Passkey registration: %v", err)
	}
	current, err = user.NewService(user.NewStore(schema.pool)).GetByID(ctx, current.ID)
	if err != nil {
		t.Fatalf("reload user after Passkey registration: %v", err)
	}
	userHandle := passkeyRegistrationUserHandle(t, registration)

	mini := miniredis.RunT(t)
	firstRedis := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	secondRedis := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() {
		_ = firstRedis.Close()
		_ = secondRedis.Close()
	})
	firstStore := session.NewStore(firstRedis)
	secondStore := session.NewStore(secondRedis)

	knownOptions, err := firstService.BeginKnownPasskeyAuthentication(ctx, current)
	if err != nil {
		t.Fatalf("begin known Passkey authentication: %v", err)
	}
	knownAssertion := passkeyAssertionResponse(
		t, knownOptions, passkeyTestRPID, passkeyTestOrigin,
		credentialID, userHandle, privateKey, 1,
	)
	const knownCeremonyID = "known-cross-instance-ceremony"
	knownCeremony := &session.WebAuthnCeremonyData{
		SessionData: knownOptions.Session, Purpose: "reauthentication",
	}
	if err := firstStore.SaveWebAuthnCeremony(ctx, knownCeremonyID, knownCeremony, 5*time.Minute); err != nil {
		t.Fatalf("save known Passkey ceremony: %v", err)
	}
	loadedKnown, err := secondStore.GetWebAuthnCeremony(ctx, knownCeremonyID)
	if err != nil {
		t.Fatalf("load known ceremony through second client: %v", err)
	}
	knownResult, err := secondService.FinishKnownPasskeyAuthentication(
		ctx, current, loadedKnown.SessionData, knownAssertion,
		mfa.ChallengeCommitGate{
			AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
			Consume: func(ctx context.Context) error {
				_, consumeErr := secondStore.ConsumeWebAuthnCeremony(ctx, knownCeremonyID)
				return consumeErr
			},
		},
		"reauthentication", mfa.AuditContext{ActorID: current.ID, ActorName: current.Username},
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("finish known Passkey authentication: %v", err)
	}
	if knownResult.ID != registered.ID {
		t.Fatalf("known authentication credential=%s want=%s", knownResult.ID, registered.ID)
	}
	if _, err := firstStore.GetWebAuthnCeremony(ctx, knownCeremonyID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("known ceremony remained after cross-client consume: %v", err)
	}
	_, err = firstService.FinishKnownPasskeyAuthentication(
		ctx, current, loadedKnown.SessionData, knownAssertion,
		mfa.ChallengeCommitGate{
			AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
			Consume: func(ctx context.Context) error {
				_, consumeErr := firstStore.ConsumeWebAuthnCeremony(ctx, knownCeremonyID)
				return consumeErr
			},
		},
		"reauthentication", mfa.AuditContext{ActorID: current.ID, ActorName: current.Username},
		time.Now().UTC(),
	)
	if !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("replayed known ceremony error=%v", err)
	}

	discoverableOptions, err := firstService.BeginDiscoverablePasskeyLogin(false)
	if err != nil {
		t.Fatalf("begin discoverable Passkey login: %v", err)
	}
	discoverableAssertion := passkeyAssertionResponse(
		t, discoverableOptions, passkeyTestRPID, passkeyTestOrigin,
		credentialID, userHandle, privateKey, 2,
	)
	const discoverableCeremonyID = "discoverable-cross-instance-ceremony"
	discoverableCeremony := &session.WebAuthnCeremonyData{
		SessionData: discoverableOptions.Session, Purpose: "login",
	}
	if err := firstStore.SaveWebAuthnCeremony(ctx, discoverableCeremonyID, discoverableCeremony, 5*time.Minute); err != nil {
		t.Fatalf("save discoverable Passkey ceremony: %v", err)
	}
	loadedDiscoverable, err := secondStore.GetWebAuthnCeremony(ctx, discoverableCeremonyID)
	if err != nil {
		t.Fatalf("load discoverable ceremony through second client: %v", err)
	}
	discoverableResult, err := secondService.FinishDiscoverablePasskeyLogin(
		ctx, loadedDiscoverable.SessionData, discoverableAssertion,
		func(ctx context.Context) error {
			_, consumeErr := secondStore.ConsumeWebAuthnCeremony(ctx, discoverableCeremonyID)
			return consumeErr
		},
		mfa.AuditContext{}, time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("finish discoverable Passkey login: %v", err)
	}
	if discoverableResult.UserID != current.ID || discoverableResult.Credential.ID != registered.ID {
		t.Fatalf("discoverable authentication=%#v", discoverableResult)
	}
	if _, err := firstStore.GetWebAuthnCeremony(ctx, discoverableCeremonyID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("discoverable ceremony remained after cross-client consume: %v", err)
	}

	var signCount int64
	var cloneWarning bool
	var lastUsedAt *time.Time
	var loginAuditCount int
	if err := schema.pool.QueryRow(ctx, `
		SELECT credential.sign_count,credential.clone_warning,credential.last_used_at,
		       (SELECT COUNT(*) FROM audit_event_outbox
		        WHERE event=$2 AND aggregate_id=$3)
		FROM user_passkey_credentials AS credential WHERE credential.id=$1
	`, registered.ID, models.AuditPasskeyLogin, registered.ID.String()).Scan(
		&signCount, &cloneWarning, &lastUsedAt, &loginAuditCount,
	); err != nil {
		t.Fatalf("load assertion result state: %v", err)
	}
	if signCount != 2 || cloneWarning || lastUsedAt == nil || loginAuditCount != 2 {
		t.Fatalf("assertion state: sign_count=%d clone_warning=%t last_used_at=%v audits=%d", signCount, cloneWarning, lastUsedAt, loginAuditCount)
	}
}

func TestDiscoverablePasskeyResolverDatabaseFailureIsNotInvalidCredential(t *testing.T) {
	schema := newPasskeyTestSchema(t)
	ctx := context.Background()
	service := newPasskeyTestService(t, schema, passkeyTestRPID)
	current := registrationTestUser("passkey-resolver-failure", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, current)
	registration, err := service.BeginPasskeyRegistration(ctx, current)
	if err != nil {
		t.Fatalf("begin Passkey registration: %v", err)
	}
	creation, credentialID, _, privateKey := passkeyRegistrationResponse(
		t, registration, passkeyTestRPID, passkeyTestOrigin,
	)
	if _, err := service.FinishPasskeyRegistration(
		ctx, current,
		mfa.AuthenticationBinding{AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion},
		"Resolver failure", registration.Session, creation,
		mfa.ChallengeCommitGate{
			AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
			Consume: func(context.Context) error { return nil },
		},
		mfa.AuditContext{ActorID: current.ID, ActorName: current.Username}, time.Now().UTC(),
	); err != nil {
		t.Fatalf("finish Passkey registration: %v", err)
	}
	loginOptions, err := service.BeginDiscoverablePasskeyLogin(false)
	if err != nil {
		t.Fatalf("begin discoverable Passkey login: %v", err)
	}
	assertion := passkeyAssertionResponse(
		t, loginOptions, passkeyTestRPID, passkeyTestOrigin,
		credentialID, passkeyRegistrationUserHandle(t, registration), privateKey, 1,
	)
	if _, err := schema.pool.Exec(ctx, `DROP TABLE user_passkey_credentials`); err != nil {
		t.Fatalf("remove credential table for resolver failure: %v", err)
	}
	consumed := false
	_, err = service.FinishDiscoverablePasskeyLogin(
		ctx, loginOptions.Session, assertion,
		func(context.Context) error { consumed = true; return nil },
		mfa.AuditContext{}, time.Now().UTC(),
	)
	if err == nil || errors.Is(err, mfa.ErrInvalidPasskey) || !strings.Contains(err.Error(), "resolving discoverable Passkey") {
		t.Fatalf("resolver infrastructure failure classification=%v", err)
	}
	if consumed {
		t.Fatal("resolver infrastructure failure consumed the WebAuthn ceremony")
	}
}

func newPasskeyTestSchema(t *testing.T) *postgresTestSchema {
	t.Helper()
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run Passkey migrations: %v", err)
	}
	return schema
}

func newPasskeyTestService(t *testing.T, schema *postgresTestSchema, rpID string) *mfa.Service {
	t.Helper()
	service, err := mfa.NewService(schema.pool, mfa.Options{
		ActiveKeyID: passkeyTestKeyID,
		MasterKeys:  map[string][]byte{passkeyTestKeyID: passkeyTestMasterKey},
		Passkeys: &mfa.PasskeyConfig{
			RPID: rpID, RPDisplayName: "Nyauth Test", RPOrigins: []string{"https://" + rpID},
		},
	})
	if err != nil {
		t.Fatalf("create Passkey service for %s: %v", rpID, err)
	}
	return service
}

func passkeyRegistrationResponse(
	t *testing.T,
	options mfa.PasskeyCreationOptions,
	rpID, origin string,
) (*protocol.ParsedCredentialCreationData, []byte, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate WebAuthn test key: %v", err)
	}
	x := privateKey.PublicKey.X.FillBytes(make([]byte, 32))
	y := privateKey.PublicKey.Y.FillBytes(make([]byte, 32))
	credentialPublicKey, err := webauthncbor.Marshal(map[int]any{
		1:  2,
		3:  -7,
		-1: 1,
		-2: x,
		-3: y,
	})
	if err != nil {
		t.Fatalf("encode COSE credential key: %v", err)
	}
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("generate credential ID: %v", err)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	authenticatorData := make([]byte, 0, 37+16+2+len(credentialID)+len(credentialPublicKey))
	authenticatorData = append(authenticatorData, rpIDHash[:]...)
	authenticatorData = append(authenticatorData, byte(0x01|0x04|0x40)) // UP, UV, AT.
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, 0)
	authenticatorData = append(authenticatorData, counter...)
	authenticatorData = append(authenticatorData, make([]byte, 16)...)
	credentialLength := make([]byte, 2)
	binary.BigEndian.PutUint16(credentialLength, uint16(len(credentialID)))
	authenticatorData = append(authenticatorData, credentialLength...)
	authenticatorData = append(authenticatorData, credentialID...)
	authenticatorData = append(authenticatorData, credentialPublicKey...)
	attestationObject, err := cbor.Marshal(map[string]any{
		"fmt": "none", "authData": authenticatorData, "attStmt": map[string]any{},
	})
	if err != nil {
		t.Fatalf("encode attestation object: %v", err)
	}
	clientDataJSON, err := json.Marshal(map[string]any{
		"type": "webauthn.create", "challenge": options.PublicKey.Challenge.String(),
		"origin": origin, "crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("encode client data: %v", err)
	}
	encodedCredentialID := base64.RawURLEncoding.EncodeToString(credentialID)
	payload, err := json.Marshal(map[string]any{
		"id": encodedCredentialID, "rawId": encodedCredentialID, "type": "public-key",
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{"credProps": map[string]any{"rk": true}},
		"response": map[string]any{
			"clientDataJSON":     base64.RawURLEncoding.EncodeToString(clientDataJSON),
			"attestationObject":  base64.RawURLEncoding.EncodeToString(attestationObject),
			"transports":         []string{"internal"},
			"publicKeyAlgorithm": -7,
		},
	})
	if err != nil {
		t.Fatalf("encode credential creation response: %v", err)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(payload)
	if err != nil {
		t.Fatalf("parse credential creation response: %v", err)
	}
	return parsed, credentialID, credentialPublicKey, privateKey
}

func passkeyRegistrationUserHandle(t *testing.T, options mfa.PasskeyCreationOptions) []byte {
	t.Helper()
	handle, ok := options.PublicKey.User.ID.(protocol.URLEncodedBase64)
	if !ok {
		t.Fatalf("registration user handle type=%T want protocol.URLEncodedBase64", options.PublicKey.User.ID)
	}
	return append([]byte(nil), handle...)
}

func passkeyAssertionResponse(
	t *testing.T,
	options mfa.PasskeyRequestOptions,
	rpID, origin string,
	credentialID, userHandle []byte,
	privateKey *ecdsa.PrivateKey,
	signCount uint32,
) *protocol.ParsedCredentialAssertionData {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte(rpID))
	authenticatorData := make([]byte, 37)
	copy(authenticatorData, rpIDHash[:])
	authenticatorData[32] = 0x01 | 0x04 // UP and UV.
	binary.BigEndian.PutUint32(authenticatorData[33:], signCount)
	clientDataJSON, err := json.Marshal(map[string]any{
		"type": "webauthn.get", "challenge": options.PublicKey.Challenge.String(),
		"origin": origin, "crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("encode assertion client data: %v", err)
	}
	clientDataHash := sha256.Sum256(clientDataJSON)
	signedData := make([]byte, 0, len(authenticatorData)+len(clientDataHash))
	signedData = append(signedData, authenticatorData...)
	signedData = append(signedData, clientDataHash[:]...)
	signedHash := sha256.Sum256(signedData)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, signedHash[:])
	if err != nil {
		t.Fatalf("sign Passkey assertion: %v", err)
	}
	encodedCredentialID := base64.RawURLEncoding.EncodeToString(credentialID)
	response := map[string]any{
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
		"authenticatorData": base64.RawURLEncoding.EncodeToString(authenticatorData),
		"signature":         base64.RawURLEncoding.EncodeToString(signature),
	}
	if len(userHandle) > 0 {
		response["userHandle"] = base64.RawURLEncoding.EncodeToString(userHandle)
	}
	payload, err := json.Marshal(map[string]any{
		"id": encodedCredentialID, "rawId": encodedCredentialID, "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": response,
	})
	if err != nil {
		t.Fatalf("encode credential assertion response: %v", err)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(payload)
	if err != nil {
		t.Fatalf("parse credential assertion response: %v", err)
	}
	return parsed
}

func passkeyTestAAD(rpID string, rowID, userID uuid.UUID, credentialID []byte) []byte {
	value := make([]byte, 0, len(rpID)+1+16+16+1+len(credentialID))
	value = append(value, rpID...)
	value = append(value, 0)
	value = append(value, rowID[:]...)
	value = append(value, userID[:]...)
	value = append(value, 0)
	value = append(value, credentialID...)
	return value
}

func tamperPasskeyEnvelope(t *testing.T, envelope string) string {
	t.Helper()
	version, keyID, payload, err := crypto.ParseEnvelope(envelope)
	if err != nil {
		t.Fatalf("parse Passkey envelope for tampering: %v", err)
	}
	sealed, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || len(sealed) == 0 {
		t.Fatalf("decode Passkey envelope for tampering: bytes=%d err=%v", len(sealed), err)
	}
	sealed[len(sealed)/2] ^= 0x01
	return strings.Join([]string{version, keyID, base64.RawURLEncoding.EncodeToString(sealed)}, ":")
}
