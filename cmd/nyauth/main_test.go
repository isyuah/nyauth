package main

import "testing"

func TestParseCommand(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		command string
		rest    []string
		wantErr bool
	}{
		{name: "default serve", command: commandServe},
		{name: "legacy flags serve", args: []string{"-config", "config.yaml"}, command: commandServe, rest: []string{"-config", "config.yaml"}},
		{name: "explicit serve", args: []string{"serve", "-config", "config.yaml"}, command: commandServe, rest: []string{"-config", "config.yaml"}},
		{name: "migrate", args: []string{"migrate", "-config", "config.yaml"}, command: commandMigrate, rest: []string{"-config", "config.yaml"}},
		{name: "unknown", args: []string{"rollback"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, rest, err := parseCommand(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v", err)
			}
			if got != tt.command {
				t.Errorf("command = %q, want %q", got, tt.command)
			}
			if len(rest) != len(tt.rest) {
				t.Fatalf("rest = %#v, want %#v", rest, tt.rest)
			}
			for i := range rest {
				if rest[i] != tt.rest[i] {
					t.Errorf("rest[%d] = %q, want %q", i, rest[i], tt.rest[i])
				}
			}
		})
	}
}
