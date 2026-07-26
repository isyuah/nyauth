package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureRuntimePrivileges grants the configured runtime role access to the
// migrated application schema while keeping schema ownership and DDL with the
// migration role.
func EnsureRuntimePrivileges(ctx context.Context, pool *pgxpool.Pool, runtimeRole string) error {
	runtimeRole = strings.TrimSpace(runtimeRole)
	if runtimeRole == "" {
		return fmt.Errorf("runtime database role is required")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting runtime privilege transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var schemaName string
	var migrationRole string
	if err := tx.QueryRow(ctx, `SELECT current_schema(), current_user`).Scan(&schemaName, &migrationRole); err != nil {
		return fmt.Errorf("resolving database privilege scope: %w", err)
	}
	if schemaName == "" {
		return fmt.Errorf("database search_path does not resolve to an application schema")
	}

	var roleExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, runtimeRole).Scan(&roleExists); err != nil {
		return fmt.Errorf("checking runtime database role: %w", err)
	}
	if !roleExists {
		return fmt.Errorf("runtime database role %q does not exist", runtimeRole)
	}

	schemaIdentifier := pgx.Identifier{schemaName}.Sanitize()
	runtimeIdentifier := pgx.Identifier{runtimeRole}.Sanitize()
	migrationIdentifier := pgx.Identifier{migrationRole}.Sanitize()
	migrationsTable := pgx.Identifier{schemaName, "schema_migrations"}.Sanitize()
	existingTypes, err := runtimeTypeIdentifiers(ctx, tx, schemaName)
	if err != nil {
		return err
	}

	statements := []string{
		"REVOKE CREATE ON SCHEMA " + schemaIdentifier + " FROM " + runtimeIdentifier,
		"GRANT USAGE ON SCHEMA " + schemaIdentifier + " TO " + runtimeIdentifier,
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA " + schemaIdentifier + " TO " + runtimeIdentifier,
		"GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA " + schemaIdentifier + " TO " + runtimeIdentifier,
		"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA " + schemaIdentifier + " TO " + runtimeIdentifier,
		"REVOKE ALL PRIVILEGES ON TABLE " + migrationsTable + " FROM PUBLIC",
		"REVOKE ALL PRIVILEGES ON TABLE " + migrationsTable + " FROM " + runtimeIdentifier,
		"GRANT SELECT ON TABLE " + migrationsTable + " TO " + runtimeIdentifier,
		"ALTER DEFAULT PRIVILEGES FOR ROLE " + migrationIdentifier + " IN SCHEMA " + schemaIdentifier + " GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO " + runtimeIdentifier,
		"ALTER DEFAULT PRIVILEGES FOR ROLE " + migrationIdentifier + " IN SCHEMA " + schemaIdentifier + " GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO " + runtimeIdentifier,
		"ALTER DEFAULT PRIVILEGES FOR ROLE " + migrationIdentifier + " IN SCHEMA " + schemaIdentifier + " GRANT EXECUTE ON FUNCTIONS TO " + runtimeIdentifier,
		"ALTER DEFAULT PRIVILEGES FOR ROLE " + migrationIdentifier + " IN SCHEMA " + schemaIdentifier + " GRANT USAGE ON TYPES TO " + runtimeIdentifier,
	}
	if len(existingTypes) > 0 {
		statements = append(statements, "GRANT USAGE ON TYPE "+strings.Join(existingTypes, ", ")+" TO "+runtimeIdentifier)
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return fmt.Errorf("applying runtime database privileges: %w", err)
		}
	}
	if err := validateEffectiveRuntimePrivileges(ctx, tx, runtimeRole, schemaName); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing runtime database privileges: %w", err)
	}
	return nil
}

func runtimeTypeIdentifiers(ctx context.Context, tx pgx.Tx, schemaName string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT t.typname
		FROM pg_type AS t
		JOIN pg_namespace AS n ON n.oid = t.typnamespace
		LEFT JOIN pg_class AS c ON c.oid = t.typrelid
		WHERE n.nspname = $1
		  AND (
			t.typtype IN ('d', 'e', 'r', 'm')
			OR (t.typtype = 'b' AND t.typelem = 0)
			OR (t.typtype = 'c' AND c.relkind = 'c')
		  )
		ORDER BY t.typname
	`, schemaName)
	if err != nil {
		return nil, fmt.Errorf("listing application schema types: %w", err)
	}
	defer rows.Close()

	var identifiers []string
	for rows.Next() {
		var typeName string
		if err := rows.Scan(&typeName); err != nil {
			return nil, fmt.Errorf("reading application schema type: %w", err)
		}
		identifiers = append(identifiers, pgx.Identifier{schemaName, typeName}.Sanitize())
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing application schema types: %w", err)
	}
	return identifiers, nil
}

func validateEffectiveRuntimePrivileges(ctx context.Context, tx pgx.Tx, runtimeRole, schemaName string) error {
	var canCreateSchema bool
	var canReadMigrations bool
	var canModifyMigrations bool
	var hasRoleMembership bool
	if err := tx.QueryRow(ctx, `
		SELECT
			has_schema_privilege($1, $2, 'CREATE'),
			has_table_privilege($1, format('%I.%I', $2, 'schema_migrations'), 'SELECT'),
			has_table_privilege($1, format('%I.%I', $2, 'schema_migrations'), 'INSERT')
				OR has_table_privilege($1, format('%I.%I', $2, 'schema_migrations'), 'UPDATE')
				OR has_table_privilege($1, format('%I.%I', $2, 'schema_migrations'), 'DELETE')
				OR has_table_privilege($1, format('%I.%I', $2, 'schema_migrations'), 'TRUNCATE')
				OR has_table_privilege($1, format('%I.%I', $2, 'schema_migrations'), 'REFERENCES')
				OR has_table_privilege($1, format('%I.%I', $2, 'schema_migrations'), 'TRIGGER'),
			EXISTS (
				SELECT 1 FROM pg_auth_members AS membership
				JOIN pg_roles AS member_role ON member_role.oid = membership.member
				WHERE member_role.rolname = $1
			)
	`, runtimeRole, schemaName).Scan(&canCreateSchema, &canReadMigrations, &canModifyMigrations, &hasRoleMembership); err != nil {
		return fmt.Errorf("validating effective runtime database privileges: %w", err)
	}
	if hasRoleMembership {
		return fmt.Errorf("runtime database role %q must not be a member of any PostgreSQL role", runtimeRole)
	}
	if canCreateSchema {
		return fmt.Errorf("runtime database role %q retains CREATE privilege on schema %q through PUBLIC or role membership", runtimeRole, schemaName)
	}
	if !canReadMigrations || canModifyMigrations {
		return fmt.Errorf("runtime database role %q must have read-only access to schema_migrations", runtimeRole)
	}
	return nil
}

// ValidateRuntimeRole verifies that production serving traffic is connected
// with the configured non-DDL runtime identity.
func ValidateRuntimeRole(ctx context.Context, pool *pgxpool.Pool, expectedRole string) error {
	expectedRole = strings.TrimSpace(expectedRole)
	if expectedRole == "" {
		return fmt.Errorf("runtime database role is required")
	}

	var currentRole string
	var schemaName string
	var canCreate bool
	var canWriteMigrations bool
	var elevatedRole bool
	var hasRoleMembership bool
	if err := pool.QueryRow(ctx, `
		SELECT
			current_user,
			current_schema(),
			has_schema_privilege(current_user, current_schema(), 'CREATE'),
			COALESCE((
				SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls
				FROM pg_roles WHERE rolname = current_user
			), FALSE),
			COALESCE((
				SELECT has_table_privilege(current_user, c.oid, 'INSERT')
					OR has_table_privilege(current_user, c.oid, 'UPDATE')
					OR has_table_privilege(current_user, c.oid, 'DELETE')
				FROM pg_class AS c
				JOIN pg_namespace AS n ON n.oid = c.relnamespace
				WHERE n.nspname = current_schema() AND c.relname = 'schema_migrations'
			), FALSE),
			EXISTS (
				SELECT 1 FROM pg_auth_members AS membership
				JOIN pg_roles AS member_role ON member_role.oid = membership.member
				WHERE member_role.rolname = current_user
			)
	`).Scan(&currentRole, &schemaName, &canCreate, &elevatedRole, &canWriteMigrations, &hasRoleMembership); err != nil {
		return fmt.Errorf("validating runtime database identity: %w", err)
	}
	if currentRole != expectedRole {
		return fmt.Errorf("database current_user %q does not match configured runtime role %q", currentRole, expectedRole)
	}
	if elevatedRole {
		return fmt.Errorf("runtime database role %q has elevated PostgreSQL role attributes", currentRole)
	}
	if hasRoleMembership {
		return fmt.Errorf("runtime database role %q must not be a member of any PostgreSQL role", currentRole)
	}
	if schemaName == "" {
		return fmt.Errorf("database search_path does not resolve to an application schema")
	}
	if canCreate {
		return fmt.Errorf("runtime database role %q must not have CREATE privilege on schema %q", currentRole, schemaName)
	}
	if canWriteMigrations {
		return fmt.Errorf("runtime database role %q must not write schema_migrations", currentRole)
	}
	return nil
}
