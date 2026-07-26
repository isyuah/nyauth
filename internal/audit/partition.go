package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const auditPartitionLockID int64 = 0x4e59415544 // "NYAUD"

// RetentionResult describes the rows and complete monthly partitions removed
// by one audit retention pass.
type RetentionResult struct {
	DeletedRows       int64
	DroppedPartitions int
}

// EnsureMonthlyPartitions creates the previous, current, and requested future
// UTC month partitions. Keeping the previous month available lets a delayed
// outbox event cross a month boundary without losing its original timestamp.
func (s *Store) EnsureMonthlyPartitions(ctx context.Context, now time.Time, monthsAhead int) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("audit store is unavailable")
	}
	if monthsAhead < 1 || monthsAhead > 24 {
		return fmt.Errorf("audit partition horizon must be between 1 and 24 months")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting audit partition maintenance: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockAuditPartitionDDL(ctx, tx); err != nil {
		return err
	}
	month := auditMonthStart(now).AddDate(0, -1, 0)
	for offset := 0; offset <= monthsAhead+1; offset++ {
		if err := ensureAuditPartitionTx(ctx, tx, month.AddDate(0, offset, 0)); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing audit partition maintenance: %w", err)
	}
	return nil
}

// ApplyRetention drops complete monthly partitions older than cutoff and then
// deletes any expired rows from the boundary partition. Partition names are
// discovered from PostgreSQL catalogs and parsed strictly before use as SQL
// identifiers.
func (s *Store) ApplyRetention(ctx context.Context, cutoff time.Time) (RetentionResult, error) {
	var result RetentionResult
	if s == nil || s.db == nil {
		return result, fmt.Errorf("audit store is unavailable")
	}
	if cutoff.IsZero() {
		return result, fmt.Errorf("audit retention cutoff is required")
	}
	cutoff = cutoff.UTC()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return result, fmt.Errorf("starting audit retention maintenance: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockAuditPartitionDDL(ctx, tx); err != nil {
		return result, err
	}

	rows, err := tx.Query(ctx, `
		SELECT child.relname
		FROM pg_inherits
		JOIN pg_class parent ON parent.oid = inhparent
		JOIN pg_class child ON child.oid = inhrelid
		JOIN pg_namespace namespace ON namespace.oid = parent.relnamespace
		WHERE namespace.nspname = current_schema() AND parent.relname = 'audit_logs'
	`)
	if err != nil {
		return result, fmt.Errorf("listing audit partitions: %w", err)
	}
	partitionNames := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return result, fmt.Errorf("scanning audit partition: %w", err)
		}
		partitionNames = append(partitionNames, name)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return result, fmt.Errorf("iterating audit partitions: %w", err)
	}
	rows.Close()

	for _, name := range partitionNames {
		month, ok := parseAuditPartitionName(name)
		if !ok || month.AddDate(0, 1, 0).After(cutoff) {
			continue
		}
		if _, err := tx.Exec(ctx, "DROP TABLE IF EXISTS "+pgx.Identifier{name}.Sanitize()); err != nil {
			return result, fmt.Errorf("dropping expired audit partition %s: %w", name, err)
		}
		result.DroppedPartitions++
	}

	tag, err := tx.Exec(ctx, `DELETE FROM audit_logs WHERE created_at < $1`, cutoff)
	if err != nil {
		return result, fmt.Errorf("deleting expired boundary audit rows: %w", err)
	}
	result.DeletedRows = tag.RowsAffected()
	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("committing audit retention maintenance: %w", err)
	}
	return result, nil
}

func lockAuditPartitionDDL(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditPartitionLockID); err != nil {
		return fmt.Errorf("locking audit partition maintenance: %w", err)
	}
	return nil
}

func ensureAuditPartitionTx(ctx context.Context, tx pgx.Tx, at time.Time) error {
	month := auditMonthStart(at)
	name := auditPartitionName(month)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		return fmt.Errorf("checking audit partition %s: %w", name, err)
	}
	if exists {
		return nil
	}
	if err := lockAuditPartitionDDL(ctx, tx); err != nil {
		return err
	}
	// A concurrent transaction may have created the partition before this
	// transaction acquired the DDL lock.
	if err := tx.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		return fmt.Errorf("rechecking audit partition %s: %w", name, err)
	}
	if exists {
		return nil
	}
	statement := fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %s PARTITION OF audit_logs FOR VALUES FROM (%s) TO (%s)",
		pgx.Identifier{name}.Sanitize(),
		quoteAuditPartitionBoundary(month),
		quoteAuditPartitionBoundary(month.AddDate(0, 1, 0)),
	)
	if _, err := tx.Exec(ctx, statement); err != nil {
		return fmt.Errorf("ensuring audit partition %s: %w", name, err)
	}
	return nil
}

func auditMonthStart(value time.Time) time.Time {
	value = value.UTC()
	return time.Date(value.Year(), value.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func auditPartitionName(month time.Time) string {
	return "audit_logs_" + auditMonthStart(month).Format("2006_01")
}

func parseAuditPartitionName(name string) (time.Time, bool) {
	const prefix = "audit_logs_"
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+7 {
		return time.Time{}, false
	}
	parsed, err := time.Parse("2006_01", strings.TrimPrefix(name, prefix))
	if err != nil || auditPartitionName(parsed) != name {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func quoteAuditPartitionBoundary(value time.Time) string {
	// The value is generated locally, not supplied by a request. Keeping the
	// explicit TIMESTAMPTZ cast also makes UTC boundaries independent of the
	// database session time zone.
	return "TIMESTAMPTZ '" + value.UTC().Format(time.RFC3339) + "'"
}
