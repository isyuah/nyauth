package passwordpolicy

import "testing"

func TestValidateUsesUTF8ByteBounds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		password string
		valid    bool
	}{
		{name: "minimum", password: "123456789012", valid: true},
		{name: "too short", password: "12345678901", valid: false},
		{name: "unicode bytes", password: "密码密码密码密码", valid: true},
		{name: "invalid UTF-8", password: string([]byte{0xff, 0xfe, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'}), valid: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(test.password)
			if (err == nil) != test.valid {
				t.Fatalf("Validate() error = %v, valid=%v", err, test.valid)
			}
		})
	}
}
