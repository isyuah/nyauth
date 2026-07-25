package database

import "testing"

func TestValidateSchemaState(t *testing.T) {
	tests := []struct {
		name    string
		version int64
		dirty   bool
		rows    int64
		wantErr bool
	}{
		{name: "current", version: SchemaVersion, rows: 1}, {name: "missing", rows: 0, wantErr: true}, {name: "legacy multi row", version: 8, rows: 8, wantErr: true}, {name: "dirty", version: SchemaVersion, dirty: true, rows: 1, wantErr: true}, {name: "old", version: SchemaVersion - 1, rows: 1, wantErr: true}, {name: "future", version: SchemaVersion + 1, rows: 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateSchemaState(tt.version, tt.dirty, tt.rows); (err != nil) != tt.wantErr {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
