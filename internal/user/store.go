package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/pkg/models"
)

var ErrLastActiveAdmin = errors.New("cannot remove the last active administrator")

// Store handles user persistence.
type Store struct {
	db *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

const userSelectCols = `id, username, email, password_hash, display_name, avatar_url, status, role, auth_version, must_change_password, last_login_at, last_login_ip, metadata, created_at, updated_at`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (*models.User, error) {
	u := &models.User{}
	if err := row.Scan(
		&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.DisplayName, &u.AvatarURL,
		&u.Status, &u.Role, &u.AuthVersion, &u.MustChangePassword, &u.LastLoginAt,
		&u.LastLoginIP, &u.Metadata, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) Create(ctx context.Context, u *models.User) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO users (
			id, username, email, password_hash, display_name, avatar_url,
			status, role, auth_version, must_change_password, metadata
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, u.ID, u.Username, u.Email, u.PasswordHash, u.DisplayName, u.AvatarURL,
		u.Status, u.Role, u.AuthVersion, u.MustChangePassword, u.Metadata)
	if err != nil {
		return fmt.Errorf("inserting user: %w", err)
	}
	return nil
}

func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE id=$1`, id))
	if err != nil {
		return nil, fmt.Errorf("getting user by ID: %w", err)
	}
	return u, nil
}

func (s *Store) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE username=$1`, username))
	if err != nil {
		return nil, fmt.Errorf("getting user by username: %w", err)
	}
	return u, nil
}

func (s *Store) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE email=$1`, email))
	if err != nil {
		return nil, fmt.Errorf("getting user by email: %w", err)
	}
	return u, nil
}

// UpdateSelf only updates fields owned by the user. The boolean arguments
// distinguish an omitted JSON field from a request that clears the value.
func (s *Store) UpdateSelf(ctx context.Context, id uuid.UUID, req models.UpdateUserRequest) (*models.User, error) {
	var email any
	if req.Email != nil && *req.Email != "" {
		email = *req.Email
	}
	var displayName any
	if req.DisplayName != nil && *req.DisplayName != "" {
		displayName = *req.DisplayName
	}
	var avatarURL any
	if req.AvatarURL != nil && *req.AvatarURL != "" {
		avatarURL = *req.AvatarURL
	}

	u, err := scanUser(s.db.QueryRow(ctx, `
		UPDATE users SET
			email=CASE WHEN $2 THEN $3::text ELSE email END,
			display_name=CASE WHEN $4 THEN $5::text ELSE display_name END,
			avatar_url=CASE WHEN $6 THEN $7::text ELSE avatar_url END,
			updated_at=NOW()
		WHERE id=$1
		RETURNING `+userSelectCols,
		id, req.Email != nil, email, req.DisplayName != nil, displayName,
		req.AvatarURL != nil, avatarURL,
	))
	if err != nil {
		return nil, fmt.Errorf("updating profile: %w", err)
	}
	return u, nil
}

func (s *Store) UpdateAdmin(ctx context.Context, id uuid.UUID, req models.AdminUpdateUserRequest) (*models.User, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return nil, err
	}
	var currentStatus models.UserStatus
	var currentRole string
	if err := tx.QueryRow(ctx, `SELECT status, role FROM users WHERE id=$1 FOR UPDATE`, id).Scan(&currentStatus, &currentRole); err != nil {
		return nil, err
	}
	removesActiveAdmin := currentStatus == models.UserStatusActive && currentRole == "admin" &&
		((req.Status != nil && *req.Status != models.UserStatusActive) || (req.Role != nil && *req.Role != "admin"))
	if removesActiveAdmin {
		var count int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE status='active' AND role='admin'`).Scan(&count); err != nil {
			return nil, err
		}
		if count <= 1 {
			return nil, ErrLastActiveAdmin
		}
	}
	var email, displayName, avatarURL any
	if req.Email != nil && *req.Email != "" {
		email = *req.Email
	}
	if req.DisplayName != nil && *req.DisplayName != "" {
		displayName = *req.DisplayName
	}
	if req.AvatarURL != nil && *req.AvatarURL != "" {
		avatarURL = *req.AvatarURL
	}
	u, err := scanUser(tx.QueryRow(ctx, `
		UPDATE users SET
			email=CASE WHEN $2 THEN $3::text ELSE email END,
			display_name=CASE WHEN $4 THEN $5::text ELSE display_name END,
			avatar_url=CASE WHEN $6 THEN $7::text ELSE avatar_url END,
			auth_version=CASE WHEN $8 AND $9::text <> status THEN auth_version+1 ELSE auth_version END,
			status=CASE WHEN $8 THEN $9::text ELSE status END,
			role=CASE WHEN $10 THEN $11::text ELSE role END,
			metadata=CASE WHEN $12 THEN $13::jsonb ELSE metadata END,
			updated_at=NOW()
		WHERE id=$1 RETURNING `+userSelectCols,
		id, req.Email != nil, email, req.DisplayName != nil, displayName,
		req.AvatarURL != nil, avatarURL, req.Status != nil, req.Status,
		req.Role != nil, req.Role, req.Metadata != nil, req.Metadata,
	))
	if err != nil {
		return nil, fmt.Errorf("updating user: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return u, nil
}

// UpdatePassword changes the password, invalidates prior credentials, and sets
// whether the user must change it again at the next login.
func (s *Store) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string, mustChange bool) (*models.User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `
		UPDATE users SET password_hash=$2, auth_version=auth_version+1,
			must_change_password=$3, updated_at=NOW()
		WHERE id=$1 RETURNING `+userSelectCols, id, passwordHash, mustChange))
	if err != nil {
		return nil, fmt.Errorf("updating password: %w", err)
	}
	return u, nil
}

func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	var status models.UserStatus
	var role string
	if err := tx.QueryRow(ctx, `SELECT status, role FROM users WHERE id=$1 FOR UPDATE`, id).Scan(&status, &role); err != nil {
		return err
	}
	if status == models.UserStatusActive && role == "admin" {
		var count int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE status='active' AND role='admin'`).Scan(&count); err != nil {
			return err
		}
		if count <= 1 {
			return ErrLastActiveAdmin
		}
	}
	result, err := tx.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return tx.Commit(ctx)
}

func (s *Store) Count(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

// BootstrapAdmin creates the first user while holding a database table lock.
func (s *Store) BootstrapAdmin(ctx context.Context, u *models.User) (bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return false, err
	}
	var count int64
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return false, err
	}
	if count != 0 {
		return false, tx.Commit(ctx)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id,username,email,password_hash,display_name,status,role,auth_version,must_change_password,metadata)
		VALUES ($1,$2,$3,$4,$5,'active','admin',1,TRUE,$6)
	`, u.ID, u.Username, u.Email, u.PasswordHash, u.DisplayName, u.Metadata)
	if err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func (s *Store) List(ctx context.Context, p models.Pagination, search string) (*models.PaginatedResponse[models.User], error) {
	var total int64
	countQuery := `SELECT COUNT(*) FROM users`
	args := []any{}
	if search != "" {
		countQuery += ` WHERE username ILIKE $1 OR COALESCE(email,'') ILIKE $1 OR COALESCE(display_name,'') ILIKE $1`
		args = append(args, "%"+search+"%")
	}
	if err := s.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("counting users: %w", err)
	}
	query := `SELECT ` + userSelectCols + ` FROM users`
	listArgs := []any{p.PageSize, p.Offset()}
	if search != "" {
		query += ` WHERE username ILIKE $3 OR COALESCE(email,'') ILIKE $3 OR COALESCE(display_name,'') ILIKE $3`
		listArgs = append(listArgs, "%"+search+"%")
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2`
	rows, err := s.db.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()
	users := make([]models.User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		users = append(users, *u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating users: %w", err)
	}
	totalPages := (int(total) + p.PageSize - 1) / p.PageSize
	return &models.PaginatedResponse[models.User]{Items: users, Total: total, Page: p.Page, PageSize: p.PageSize, TotalPages: totalPages}, nil
}

func (s *Store) RecordLogin(ctx context.Context, id uuid.UUID, ip string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET last_login_at=NOW(), last_login_ip=$2, updated_at=NOW() WHERE id=$1`, id, ip)
	return err
}

// IsNotFound reports whether a store error was caused by a missing row.
func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
