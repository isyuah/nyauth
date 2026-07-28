package database_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/database"
)

func TestPasskeyBaselineScopesIdentifiersByRelyingParty(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run release baseline: %v", err)
	}
	ctx := context.Background()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,creation_source)
		VALUES ($1,$2,'active','user','legacy')
	`, userID, "passkey-schema-"+uuid.NewString()[:8]); err != nil {
		t.Fatalf("insert Passkey user: %v", err)
	}
	handle := bytes.Repeat([]byte{0x41}, 32)
	credentialID := []byte("same-credential-id")
	for _, rpID := range []string{"auth.example.test", "login.example.test"} {
		if _, err := schema.pool.Exec(ctx, `
			INSERT INTO user_passkey_handles (rp_id,user_id,user_handle)
			VALUES ($1,$2,$3)
		`, rpID, userID, handle); err != nil {
			t.Fatalf("insert handle for %s: %v", rpID, err)
		}
		if _, err := schema.pool.Exec(ctx, `
			INSERT INTO user_passkey_credentials (
				rp_id,user_id,credential_id,credential_ciphertext,name
			) VALUES ($1,$2,$3,'encrypted','test')
		`, rpID, userID, credentialID); err != nil {
			t.Fatalf("insert credential for %s: %v", rpID, err)
		}
	}
}
