package identity

import (
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsUserEmailConflictMatchesOnlyUsersEmailConstraint(t *testing.T) {
	t.Parallel()
	emailConflict := fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: "23505", ConstraintName: usersEmailUniqueConstraint})
	if !IsUserEmailConflict(emailConflict) {
		t.Fatal("users email conflict was not recognized")
	}
	for _, err := range []error{
		&pgconn.PgError{Code: "23505", ConstraintName: "users_username_key"},
		&pgconn.PgError{Code: "23505", ConstraintName: "users_email_key"},
		&pgconn.PgError{Code: "23503", ConstraintName: usersEmailUniqueConstraint},
		fmt.Errorf("unrelated"),
	} {
		if IsUserEmailConflict(err) {
			t.Fatalf("unrelated error was treated as an email conflict: %v", err)
		}
	}
}
