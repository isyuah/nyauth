package user

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/google/uuid"
)

// Store handles user persistence.
type Store struct {
	db *pgxpool.Pool
}

// NewStore creates a new user store.
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// Create inserts a new user.
func (s *Store) Create(ctx context.Context, u *models.User) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, display_name, avatar_url, status, role, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, u.ID, u.Username, u.Email, u.PasswordHash, u.DisplayName, u.AvatarURL, u.Status, u.Role, u.Metadata)
	if err != nil {
		return fmt.Errorf("inserting user: %w", err)
	}
	return nil
}

const userSelectCols = `id, username, email, password_hash, display_name, avatar_url, status, role, last_login_at, last_login_ip, metadata, created_at, updated_at`

// GetByID retrieves a user by ID.
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	u := &models.User{}
	err := s.db.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE id = $1`, id).Scan(
		&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.DisplayName, &u.AvatarURL, &u.Status, &u.Role, &u.LastLoginAt, &u.LastLoginIP, &u.Metadata, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("getting user by ID: %w", err)
	}
	return u, nil
}

// GetByUsername retrieves a user by username.
func (s *Store) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	u := &models.User{}
	err := s.db.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE username = $1`, username).Scan(
		&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.DisplayName, &u.AvatarURL, &u.Status, &u.Role, &u.LastLoginAt, &u.LastLoginIP, &u.Metadata, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("getting user by username: %w", err)
	}
	return u, nil
}

// GetByEmail retrieves a user by email.
func (s *Store) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	u := &models.User{}
	err := s.db.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE email = $1`, email).Scan(
		&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.DisplayName, &u.AvatarURL, &u.Status, &u.Role, &u.LastLoginAt, &u.LastLoginIP, &u.Metadata, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("getting user by email: %w", err)
	}
	return u, nil
}

// Update updates a user.
func (s *Store) Update(ctx context.Context, u *models.User) error {
	_, err := s.db.Exec(ctx, `
		UPDATE users SET username=$2, email=$3, display_name=$4, avatar_url=$5, status=$6, role=$7, metadata=$8, updated_at=NOW()
		WHERE id = $1
	`, u.ID, u.Username, u.Email, u.DisplayName, u.AvatarURL, u.Status, u.Role, u.Metadata)
	if err != nil {
		return fmt.Errorf("updating user: %w", err)
	}
	return nil
}

// UpdatePassword updates just the password hash.
func (s *Store) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET password_hash=$2, updated_at=NOW() WHERE id=$1`, id, passwordHash)
	return err
}

// Delete deletes a user by ID.
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	return err
}

// List retrieves users with pagination.
func (s *Store) List(ctx context.Context, p models.Pagination, search string) (*models.PaginatedResponse[models.User], error) {
	var total int64
	countQuery := `SELECT COUNT(*) FROM users`
	args := []interface{}{}

	if search != "" {
		countQuery += ` WHERE username ILIKE $1 OR email ILIKE $1 OR display_name ILIKE $1`
		args = append(args, "%"+search+"%")
	}

	if err := s.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("counting users: %w", err)
	}

	query := `SELECT ` + userSelectCols + ` FROM users`
	if search != "" {
		query += ` WHERE username ILIKE $3 OR email ILIKE $3 OR display_name ILIKE $3`
	}
	query += ` ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	listArgs := []interface{}{p.PageSize, p.Offset()}
	if search != "" {
		listArgs = append(listArgs, "%"+search+"%")
	}

	rows, err := s.db.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.DisplayName, &u.AvatarURL, &u.Status, &u.Role, &u.LastLoginAt, &u.LastLoginIP, &u.Metadata, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		users = append(users, u)
	}

	totalPages := int(total) / p.PageSize
	if int(total)%p.PageSize > 0 {
		totalPages++
	}

	return &models.PaginatedResponse[models.User]{
		Items:      users,
		Total:      total,
		Page:       p.Page,
		PageSize:   p.PageSize,
		TotalPages: totalPages,
	}, nil
}

// RecordLogin updates last_login_at and last_login_ip for a user.
func (s *Store) RecordLogin(ctx context.Context, id uuid.UUID, ip string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET last_login_at=NOW(), last_login_ip=$2, updated_at=NOW() WHERE id=$1`, id, ip)
	return err
}
