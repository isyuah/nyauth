package passwordpolicy

import (
	"errors"
	"unicode/utf8"
)

const (
	MinBytes = 12
	MaxBytes = 1024
)

var ErrInvalid = errors.New("password must be valid UTF-8 and 12 to 1024 bytes")

// Validate is the single server-side password policy used by bootstrap,
// administrative creation, password changes, and account recovery.
func Validate(password string) error {
	if len(password) < MinBytes || len(password) > MaxBytes || !utf8.ValidString(password) {
		return ErrInvalid
	}
	return nil
}
