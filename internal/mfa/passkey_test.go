package mfa

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

func TestPasskeyCredentialEnvelopeRoundTripAndAADBinding(t *testing.T) {
	t.Parallel()
	service := testPasskeyService("AUTH.EXAMPLE.TEST")
	credential := testPasskeyCredential()
	row := passkeyRow{
		ID: uuid.New(), RPID: service.passkeys.rpID, UserID: uuid.New(),
		CredentialID: append([]byte(nil), credential.ID...),
	}

	ciphertext, err := service.encryptPasskeyCredential(row.ID, row.UserID, &credential)
	if err != nil {
		t.Fatalf("encrypt credential: %v", err)
	}
	row.Ciphertext = ciphertext
	restored, err := service.decryptPasskeyCredential(row)
	if err != nil {
		t.Fatalf("decrypt credential: %v", err)
	}
	if !reflect.DeepEqual(restored, credential) {
		t.Fatalf("credential round trip mismatch\n got: %#v\nwant: %#v", restored, credential)
	}

	tests := []struct {
		name   string
		mutate func(*passkeyRow)
	}{
		{name: "RP ID", mutate: func(value *passkeyRow) { value.RPID = "other.example.test" }},
		{name: "record ID", mutate: func(value *passkeyRow) { value.ID = uuid.New() }},
		{name: "user ID", mutate: func(value *passkeyRow) { value.UserID = uuid.New() }},
		{name: "credential ID", mutate: func(value *passkeyRow) { value.CredentialID = []byte("other-credential") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tampered := row
			tampered.CredentialID = append([]byte(nil), row.CredentialID...)
			test.mutate(&tampered)
			if _, err := service.decryptPasskeyCredential(tampered); err == nil {
				t.Fatal("tampered credential envelope decrypted successfully")
			}
		})
	}
}

func TestPasskeyCredentialEnvelopePersistsAssertionState(t *testing.T) {
	t.Parallel()
	service := testPasskeyService("auth.example.test")
	credential := testPasskeyCredential()
	credential.Authenticator.SignCount = 42
	credential.Authenticator.CloneWarning = true
	credential.Flags = gowebauthn.NewCredentialFlags(
		protocol.FlagUserPresent | protocol.FlagUserVerified |
			protocol.FlagBackupEligible | protocol.FlagBackupState,
	)
	row := passkeyRow{
		ID: uuid.New(), RPID: service.passkeys.rpID, UserID: uuid.New(),
		CredentialID: append([]byte(nil), credential.ID...),
	}

	ciphertext, err := service.encryptPasskeyCredential(row.ID, row.UserID, &credential)
	if err != nil {
		t.Fatalf("encrypt updated credential: %v", err)
	}
	row.Ciphertext = ciphertext
	restored, err := service.decryptPasskeyCredential(row)
	if err != nil {
		t.Fatalf("decrypt updated credential: %v", err)
	}
	if restored.Authenticator.SignCount != 42 || !restored.Authenticator.CloneWarning {
		t.Fatalf("restored authenticator state = %#v", restored.Authenticator)
	}
	if !restored.Flags.BackupEligible || !restored.Flags.BackupState || !restored.Flags.UserVerified {
		t.Fatalf("restored credential flags = %#v", restored.Flags)
	}
}

func TestPasskeySessionPreservesLibraryStateAndRejectsAnotherRP(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Millisecond)
	original := gowebauthn.SessionData{
		Challenge:            "challenge",
		RelyingPartyID:       "auth.example.test",
		UserID:               []byte("opaque-user-handle"),
		AllowedCredentialIDs: [][]byte{[]byte("first"), []byte("second")},
		Expires:              now.Add(5 * time.Minute),
		UserVerification:     protocol.VerificationRequired,
		Extensions:           protocol.AuthenticationExtensions{"example": int64(7)},
		Mediation:            protocol.MediationConditional,
	}
	encoded, err := marshalPasskeySession(&original)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	restored, err := unmarshalPasskeySession(encoded)
	if err != nil {
		t.Fatalf("unmarshal session: %v", err)
	}
	// MessagePack preserves the instant but reconstructs timestamps in the
	// process-local location.
	restored.Expires = restored.Expires.UTC()
	if !reflect.DeepEqual(restored, original) {
		t.Fatalf("session round trip mismatch\n got: %#v\nwant: %#v", restored, original)
	}

	service := testPasskeyService("auth.example.test")
	if _, err := service.validatePasskeySession(encoded); err != nil {
		t.Fatalf("validate current RP session: %v", err)
	}
	restored.RelyingPartyID = "other.example.test"
	tampered, err := marshalPasskeySession(&restored)
	if err != nil {
		t.Fatalf("marshal other RP session: %v", err)
	}
	if _, err := service.validatePasskeySession(tampered); err != ErrInvalidPasskey {
		t.Fatalf("other RP validation error = %v, want %v", err, ErrInvalidPasskey)
	}
}

func TestPasskeyRuntimeNormalizesRPID(t *testing.T) {
	t.Parallel()
	runtime, err := newPasskeyRuntime(&PasskeyConfig{
		RPID: "  AUTH.Example.TEST  ", RPDisplayName: "Nyauth",
		RPOrigins: []string{"https://auth.example.test"},
	})
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}
	if runtime.rpID != "auth.example.test" {
		t.Fatalf("RP ID = %q", runtime.rpID)
	}
}

func TestDiscoverablePasskeyOptionsRequireUserVerification(t *testing.T) {
	t.Parallel()
	service := testPasskeyService("auth.example.test")
	options, err := service.BeginDiscoverablePasskeyLogin(true)
	if err != nil {
		t.Fatalf("begin conditional login: %v", err)
	}
	if options.Mediation != protocol.MediationConditional {
		t.Fatalf("mediation = %q", options.Mediation)
	}
	if options.PublicKey.UserVerification != protocol.VerificationRequired {
		t.Fatalf("user verification = %q", options.PublicKey.UserVerification)
	}
	if len(options.PublicKey.AllowedCredentials) != 0 {
		t.Fatalf("discoverable login unexpectedly constrained credentials: %#v", options.PublicKey.AllowedCredentials)
	}
	sessionData, err := unmarshalPasskeySession(options.Session)
	if err != nil {
		t.Fatalf("decode conditional session: %v", err)
	}
	if sessionData.RelyingPartyID != "auth.example.test" || len(sessionData.UserID) != 0 {
		t.Fatalf("discoverable session = %#v", sessionData)
	}
}

func testPasskeyService(rpID string) *Service {
	key := bytes.Repeat([]byte{0x42}, 32)
	runtime, err := newPasskeyRuntime(&PasskeyConfig{
		RPID: rpID, RPDisplayName: "Nyauth", RPOrigins: []string{"https://auth.example.test"},
	})
	if err != nil {
		panic(err)
	}
	return &Service{
		activeKeyID: "primary", masterKeys: map[string][]byte{"primary": key}, passkeys: runtime,
	}
}

func testPasskeyCredential() gowebauthn.Credential {
	return gowebauthn.Credential{
		ID:                []byte("credential-id"),
		PublicKey:         []byte{0xa5, 0x01, 0x02, 0x03},
		AttestationType:   "none",
		AttestationFormat: "none",
		Transport:         []protocol.AuthenticatorTransport{protocol.Internal, protocol.Hybrid},
		Flags:             gowebauthn.NewCredentialFlags(protocol.FlagUserPresent | protocol.FlagUserVerified),
		Authenticator: gowebauthn.Authenticator{
			AAGUID: bytes.Repeat([]byte{0x11}, 16), SignCount: 3,
			Attachment: protocol.Platform,
		},
		Attestation: gowebauthn.CredentialAttestation{
			ClientDataJSON:    []byte(`{"type":"webauthn.create"}`),
			ClientDataHash:    bytes.Repeat([]byte{0x22}, 32),
			AuthenticatorData: []byte{0x01, 0x02}, PublicKeyAlgorithm: -7,
			Object: []byte{0xa0},
		},
	}
}
