package notification

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	StatusDraft     = "draft"
	StatusPublished = "published"
	StatusArchived  = "archived"

	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"

	AudienceAuthenticated = "authenticated"
	AudienceAdmins        = "admins"
)

var (
	ErrRevisionConflict  = errors.New("announcement revision conflict")
	ErrInvalidTransition = errors.New("announcement state does not allow this operation")
	ErrNotFound          = errors.New("announcement not found")
	ErrInvalidInput      = errors.New("invalid announcement input")
)

// NotificationType is a bounded catalog. New user-visible security events must
// be added here together with their contract tests before they can be stored.
type NotificationType string

const (
	TypePasswordChanged      NotificationType = "security.password_changed"
	TypeEmailChanged         NotificationType = "security.email_changed"
	TypeMFAChanged           NotificationType = "security.mfa_changed"
	TypePasskeyChanged       NotificationType = "security.passkey_changed"
	TypeIdentityChanged      NotificationType = "security.identity_changed"
	TypeAuthorizationRevoked NotificationType = "oauth.authorization_revoked"
	TypePublisherVerified    NotificationType = "oauth.publisher_verified"
	TypePublisherRevoked     NotificationType = "oauth.publisher_revoked"
	TypeDeviceAuthorized     NotificationType = "oauth.device_authorized"
)

func (t NotificationType) Valid() bool {
	switch t {
	case TypePasswordChanged, TypeEmailChanged, TypeMFAChanged, TypePasskeyChanged,
		TypeIdentityChanged, TypeAuthorizationRevoked, TypePublisherVerified,
		TypePublisherRevoked, TypeDeviceAuthorized:
		return true
	default:
		return false
	}
}

type Announcement struct {
	ID           uuid.UUID  `json:"id"`
	Status       string     `json:"status"`
	Severity     string     `json:"severity"`
	Audience     string     `json:"audience"`
	Title        string     `json:"title"`
	Summary      string     `json:"summary"`
	BodyMarkdown string     `json:"body_markdown,omitempty"`
	BodyHTML     string     `json:"body_html,omitempty"`
	LinkURL      string     `json:"link_url,omitempty"`
	Pinned       bool       `json:"pinned"`
	StartsAt     *time.Time `json:"starts_at,omitempty"`
	EndsAt       *time.Time `json:"ends_at,omitempty"`
	PublishedAt  *time.Time `json:"published_at,omitempty"`
	ArchivedAt   *time.Time `json:"archived_at,omitempty"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy    *uuid.UUID `json:"updated_by,omitempty"`
	Revision     int64      `json:"revision"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	Read         bool       `json:"read,omitempty"`
}

type AnnouncementInput struct {
	Severity     string     `json:"severity"`
	Audience     string     `json:"audience"`
	Title        string     `json:"title"`
	Summary      string     `json:"summary"`
	BodyMarkdown string     `json:"body_markdown"`
	LinkURL      string     `json:"link_url"`
	Pinned       bool       `json:"pinned"`
	StartsAt     *time.Time `json:"starts_at"`
	EndsAt       *time.Time `json:"ends_at"`
}

type ListOptions struct {
	Page     int
	PageSize int
	Query    string
	Status   string
	Audience string
	Severity string
}

type Store struct{ db *pgxpool.Pool }

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

func validateText(name, value string, max int, required bool) error {
	value = strings.TrimSpace(value)
	if required && value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if utf8.RuneCountInString(value) > max {
		return fmt.Errorf("%s must be at most %d characters", name, max)
	}
	for _, r := range value {
		if r == '\r' || r == 0 || (unicode.IsControl(r) && r != '\n' && r != '\t') || (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069') {
			return fmt.Errorf("%s contains unsupported control characters", name)
		}
	}
	return nil
}

func normalizeInput(input AnnouncementInput, published bool) (AnnouncementInput, error) {
	input.Severity = strings.TrimSpace(input.Severity)
	input.Audience = strings.TrimSpace(input.Audience)
	input.Title = strings.TrimSpace(input.Title)
	input.Summary = strings.TrimSpace(input.Summary)
	input.BodyMarkdown = strings.TrimSpace(input.BodyMarkdown)
	input.LinkURL = strings.TrimSpace(input.LinkURL)
	if input.Severity == "" {
		input.Severity = SeverityInfo
	}
	if input.Audience == "" {
		input.Audience = AudienceAuthenticated
	}
	if input.Severity != SeverityInfo && input.Severity != SeverityWarning && input.Severity != SeverityCritical {
		return AnnouncementInput{}, errors.New("announcement severity is unsupported")
	}
	if input.Audience != AudienceAuthenticated && input.Audience != AudienceAdmins {
		return AnnouncementInput{}, errors.New("announcement audience is unsupported")
	}
	for _, field := range []struct {
		name, value string
		max         int
		required    bool
	}{
		{"announcement title", input.Title, 120, published},
		{"announcement summary", input.Summary, 240, false},
		{"announcement body", input.BodyMarkdown, 20000, published},
	} {
		if err := validateText(field.name, field.value, field.max, field.required); err != nil {
			return AnnouncementInput{}, err
		}
	}
	if input.BodyMarkdown != "" {
		if _, err := settings.RenderSiteBannerMarkdown(input.BodyMarkdown); err != nil {
			return AnnouncementInput{}, fmt.Errorf("announcement body: %w", err)
		}
	}
	if input.LinkURL != "" && !validLink(input.LinkURL) {
		return AnnouncementInput{}, errors.New("announcement link must use a root-relative path or absolute HTTPS URL")
	}
	if input.StartsAt != nil {
		v := input.StartsAt.UTC()
		input.StartsAt = &v
	}
	if input.EndsAt != nil {
		v := input.EndsAt.UTC()
		input.EndsAt = &v
	}
	if input.StartsAt != nil && input.EndsAt != nil && !input.EndsAt.After(*input.StartsAt) {
		return AnnouncementInput{}, errors.New("announcement ends_at must be later than starts_at")
	}
	return input, nil
}

func validLink(value string) bool {
	if strings.Contains(value, `\`) {
		return false
	}
	if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") {
		parsed, err := url.Parse(value)
		return err == nil && parsed.Host == "" && parsed.User == nil
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
}

const announcementColumns = `id,status,severity,audience,title,summary,body_markdown,link_url,pinned,starts_at,ends_at,published_at,archived_at,created_by,updated_by,revision,created_at,updated_at`

func scanAnnouncement(row interface{ Scan(...any) error }, bodyHTML bool) (*Announcement, error) {
	item := &Announcement{}
	var linkURL *string
	if err := row.Scan(&item.ID, &item.Status, &item.Severity, &item.Audience, &item.Title, &item.Summary, &item.BodyMarkdown, &linkURL, &item.Pinned, &item.StartsAt, &item.EndsAt, &item.PublishedAt, &item.ArchivedAt, &item.CreatedBy, &item.UpdatedBy, &item.Revision, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return nil, err
	}
	if linkURL != nil {
		item.LinkURL = *linkURL
	}
	if bodyHTML {
		item.BodyHTML, _ = settings.RenderSiteBannerMarkdown(item.BodyMarkdown)
	}
	return item, nil
}

func scanAnnouncementWithRead(row interface{ Scan(...any) error }, bodyHTML bool) (*Announcement, error) {
	item := &Announcement{}
	var linkURL *string
	if err := row.Scan(&item.ID, &item.Status, &item.Severity, &item.Audience, &item.Title, &item.Summary, &item.BodyMarkdown, &linkURL, &item.Pinned, &item.StartsAt, &item.EndsAt, &item.PublishedAt, &item.ArchivedAt, &item.CreatedBy, &item.UpdatedBy, &item.Revision, &item.CreatedAt, &item.UpdatedAt, &item.Read); err != nil {
		return nil, err
	}
	if linkURL != nil {
		item.LinkURL = *linkURL
	}
	if bodyHTML {
		item.BodyHTML, _ = settings.RenderSiteBannerMarkdown(item.BodyMarkdown)
	}
	return item, nil
}

func (s *Store) CreateAnnouncement(ctx context.Context, input AnnouncementInput, actor uuid.UUID, mutation audit.MutationAudit) (*Announcement, error) {
	if err := mutation.ValidateEvent(models.AuditAnnouncementCreated); err != nil {
		return nil, err
	}
	input, err := normalizeInput(input, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting announcement creation: %w", err)
	}
	defer tx.Rollback(ctx)
	id := uuid.New()
	item, err := scanAnnouncement(tx.QueryRow(ctx, `INSERT INTO announcements (id,severity,audience,title,summary,body_markdown,link_url,pinned,starts_at,ends_at,created_by,updated_by) VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9,$10,$11,$11) RETURNING `+announcementColumns, id, input.Severity, input.Audience, input.Title, input.Summary, input.BodyMarkdown, input.LinkURL, input.Pinned, input.StartsAt, input.EndsAt, actor), true)
	if err != nil {
		return nil, fmt.Errorf("creating announcement: %w", err)
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("announcement", id.String())); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing announcement creation: %w", err)
	}
	return item, nil
}

func (s *Store) UpdateAnnouncement(ctx context.Context, id uuid.UUID, input AnnouncementInput, expectedRevision int64, actor uuid.UUID, mutation audit.MutationAudit) (*Announcement, error) {
	if err := mutation.ValidateEvent(models.AuditAnnouncementUpdated); err != nil {
		return nil, err
	}
	if expectedRevision < 1 {
		return nil, fmt.Errorf("%w: expected revision is required", ErrInvalidInput)
	}
	input, err := normalizeInput(input, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting announcement update: %w", err)
	}
	defer tx.Rollback(ctx)
	var status string
	var currentRevision int64
	if err := tx.QueryRow(ctx, `SELECT status,revision FROM announcements WHERE id=$1 FOR UPDATE`, id).Scan(&status, &currentRevision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if currentRevision != expectedRevision {
		return nil, ErrRevisionConflict
	}
	if status == StatusPublished {
		input, err = normalizeInput(input, true)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
	}
	item, err := scanAnnouncement(tx.QueryRow(ctx, `UPDATE announcements SET severity=$2,audience=$3,title=$4,summary=$5,body_markdown=$6,link_url=NULLIF($7,''),pinned=$8,starts_at=$9,ends_at=$10,updated_by=$11,revision=revision+1,updated_at=NOW() WHERE id=$1 AND revision=$12 RETURNING `+announcementColumns, id, input.Severity, input.Audience, input.Title, input.Summary, input.BodyMarkdown, input.LinkURL, input.Pinned, input.StartsAt, input.EndsAt, actor, expectedRevision), true)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRevisionConflict
		}
		return nil, err
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("announcement", id.String())); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return item, nil
}

func (s *Store) PublishAnnouncement(ctx context.Context, id uuid.UUID, expectedRevision int64, actor uuid.UUID, mutation audit.MutationAudit) (*Announcement, error) {
	return s.transition(ctx, id, expectedRevision, actor, mutation, StatusPublished, models.AuditAnnouncementPublished)
}

func (s *Store) ArchiveAnnouncement(ctx context.Context, id uuid.UUID, expectedRevision int64, actor uuid.UUID, mutation audit.MutationAudit) (*Announcement, error) {
	return s.transition(ctx, id, expectedRevision, actor, mutation, StatusArchived, models.AuditAnnouncementArchived)
}

func (s *Store) transition(ctx context.Context, id uuid.UUID, expectedRevision int64, actor uuid.UUID, mutation audit.MutationAudit, status, event string) (*Announcement, error) {
	if err := mutation.ValidateEvent(event); err != nil {
		return nil, err
	}
	if expectedRevision < 1 {
		return nil, fmt.Errorf("%w: expected revision is required", ErrInvalidInput)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var currentStatus, title, body string
	var currentRevision int64
	if err := tx.QueryRow(ctx, `SELECT status,title,body_markdown,revision FROM announcements WHERE id=$1 FOR UPDATE`, id).Scan(&currentStatus, &title, &body, &currentRevision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if currentRevision != expectedRevision {
		return nil, ErrRevisionConflict
	}
	wantCurrent := StatusDraft
	if status == StatusArchived {
		wantCurrent = StatusPublished
	}
	if currentStatus != wantCurrent {
		return nil, ErrInvalidTransition
	}
	if status == StatusPublished {
		if _, err := normalizeInput(AnnouncementInput{Title: title, BodyMarkdown: body}, true); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
	}
	item, err := scanAnnouncement(tx.QueryRow(ctx, `UPDATE announcements SET status=$2::varchar,published_at=CASE WHEN $2::varchar='published' THEN COALESCE(published_at,NOW()) ELSE published_at END,archived_at=CASE WHEN $2::varchar='archived' THEN NOW() ELSE archived_at END,updated_by=$3,revision=revision+1,updated_at=NOW() WHERE id=$1 AND revision=$4 RETURNING `+announcementColumns, id, status, actor, expectedRevision), true)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRevisionConflict
		}
		return nil, err
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("announcement", id.String())); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return item, nil
}

func (s *Store) ListAdmin(ctx context.Context, options ListOptions) (*models.PaginatedResponse[Announcement], error) {
	options = normalizeListOptions(options)
	args := []any{}
	where := []string{"TRUE"}
	add := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }
	if options.Query != "" {
		p := add("%" + options.Query + "%")
		where = append(where, "(title ILIKE "+p+" OR summary ILIKE "+p+")")
	}
	if options.Status != "" {
		where = append(where, "status="+add(options.Status))
	}
	if options.Audience != "" {
		where = append(where, "audience="+add(options.Audience))
	}
	if options.Severity != "" {
		where = append(where, "severity="+add(options.Severity))
	}
	return list(ctx, s.db, strings.Join(where, " AND "), args, options, false, uuid.Nil)
}

func (s *Store) GetAdmin(ctx context.Context, id uuid.UUID) (*Announcement, error) {
	item, err := scanAnnouncement(s.db.QueryRow(ctx, `SELECT `+announcementColumns+` FROM announcements WHERE id=$1`, id), true)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return item, err
}

func (s *Store) ListForUser(ctx context.Context, userID uuid.UUID, isAdmin bool, options ListOptions) (*models.PaginatedResponse[Announcement], error) {
	options = normalizeListOptions(options)
	args := []any{}
	where := []string{"a.status='published'", "(a.starts_at IS NULL OR a.starts_at<=NOW())", "(a.ends_at IS NULL OR a.ends_at>NOW())"}
	if !isAdmin {
		where = append(where, "a.audience='authenticated'")
	}
	return list(ctx, s.db, strings.Join(where, " AND "), args, options, true, userID)
}

func normalizeListOptions(options ListOptions) ListOptions {
	if options.Page < 1 {
		options.Page = 1
	}
	if options.PageSize < 1 || options.PageSize > 100 {
		options.PageSize = 20
	}
	options.Query = strings.TrimSpace(options.Query)
	return options
}

func list(ctx context.Context, db *pgxpool.Pool, where string, args []any, options ListOptions, userRead bool, userID uuid.UUID) (*models.PaginatedResponse[Announcement], error) {
	countArgs := append([]any(nil), args...)
	var total int64
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM announcements AS a WHERE `+where, countArgs...).Scan(&total); err != nil {
		return nil, err
	}
	limitPos := len(args) + 1
	offsetPos := len(args) + 2
	args = append(args, options.PageSize, (options.Page-1)*options.PageSize)
	selectList := "a." + strings.ReplaceAll(announcementColumns, ",", ",a.")
	query := `SELECT ` + selectList
	if userRead {
		query += `,EXISTS(SELECT 1 FROM announcement_reads AS ar WHERE ar.announcement_id=a.id AND ar.user_id=$` + fmt.Sprint(len(args)+1) + ` AND ar.read_revision>=a.revision)`
		args = append(args, userID)
	}
	query += ` FROM announcements AS a WHERE ` + where + ` ORDER BY a.pinned DESC,a.starts_at DESC NULLS LAST,a.updated_at DESC,a.id DESC LIMIT $` + fmt.Sprint(limitPos) + ` OFFSET $` + fmt.Sprint(offsetPos)
	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Announcement, 0, options.PageSize)
	for rows.Next() {
		var item *Announcement
		var scanErr error
		if userRead {
			item, scanErr = scanAnnouncementWithRead(rows, false)
		} else {
			item, scanErr = scanAnnouncement(rows, false)
		}
		if scanErr != nil {
			return nil, scanErr
		}
		if userRead {
			redactPublicAnnouncement(item)
		}
		items = append(items, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	pages := int((total + int64(options.PageSize) - 1) / int64(options.PageSize))
	return &models.PaginatedResponse[Announcement]{Items: items, Total: total, Page: options.Page, PageSize: options.PageSize, TotalPages: pages}, nil
}

func (s *Store) GetForUser(ctx context.Context, id, userID uuid.UUID, isAdmin bool) (*Announcement, error) {
	where := `a.id=$1 AND a.status='published' AND (a.starts_at IS NULL OR a.starts_at<=NOW()) AND (a.ends_at IS NULL OR a.ends_at>NOW())`
	args := []any{id, userID}
	if !isAdmin {
		where += ` AND a.audience='authenticated'`
	}
	row := s.db.QueryRow(ctx, `SELECT `+strings.ReplaceAll(announcementColumns, ",", ",a.")+`,EXISTS(SELECT 1 FROM announcement_reads ar WHERE ar.announcement_id=a.id AND ar.user_id=$2 AND ar.read_revision>=a.revision) FROM announcements a WHERE `+where, args...)
	item, err := scanAnnouncementWithRead(row, true)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	redactPublicAnnouncement(item)
	return item, nil
}

func redactPublicAnnouncement(item *Announcement) {
	if item == nil {
		return
	}
	item.BodyMarkdown = ""
	item.CreatedBy = nil
	item.UpdatedBy = nil
}

func (s *Store) MarkAnnouncementRead(ctx context.Context, id, userID uuid.UUID, isAdmin bool) error {
	audience := `audience='authenticated'`
	if isAdmin {
		audience = `audience IN ('authenticated','admins')`
	}
	tag, err := s.db.Exec(ctx, `
		INSERT INTO announcement_reads(announcement_id,user_id,read_revision)
		SELECT id,$2,revision FROM announcements
		WHERE id=$1 AND status='published' AND (`+audience+`)
		  AND (starts_at IS NULL OR starts_at<=NOW()) AND (ends_at IS NULL OR ends_at>NOW())
		ON CONFLICT (announcement_id,user_id) DO UPDATE
		SET read_revision=GREATEST(announcement_reads.read_revision,EXCLUDED.read_revision),read_at=NOW()
	`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UnreadAnnouncementCount(ctx context.Context, userID uuid.UUID, isAdmin bool) (int64, error) {
	audience := `a.audience='authenticated'`
	if isAdmin {
		audience = `a.audience IN ('authenticated','admins')`
	}
	var count int64
	err := s.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM announcements AS a
		LEFT JOIN announcement_reads AS r ON r.announcement_id=a.id AND r.user_id=$1
		WHERE a.status='published' AND (`+audience+`)
		  AND (a.starts_at IS NULL OR a.starts_at<=NOW()) AND (a.ends_at IS NULL OR a.ends_at>NOW())
		  AND (r.read_revision IS NULL OR r.read_revision<a.revision)
	`, userID).Scan(&count)
	return count, err
}

type Notification struct {
	ID           uuid.UUID        `json:"id"`
	UserID       uuid.UUID        `json:"-"`
	Type         NotificationType `json:"type"`
	Severity     string           `json:"severity"`
	Title        string           `json:"title"`
	BodyMarkdown string           `json:"-"`
	BodyHTML     string           `json:"body_html"`
	LinkURL      string           `json:"link_url,omitempty"`
	SourceType   string           `json:"source_type,omitempty"`
	SourceID     string           `json:"source_id,omitempty"`
	CreatedAt    time.Time        `json:"created_at"`
	ReadAt       *time.Time       `json:"read_at,omitempty"`
	ExpiresAt    *time.Time       `json:"expires_at,omitempty"`
}

type NotificationInput struct {
	UserID                                                                  uuid.UUID
	Type                                                                    NotificationType
	Severity, Title, BodyMarkdown, LinkURL, SourceType, SourceID, DedupeKey string
	ExpiresAt                                                               *time.Time
}

type MessageKind string

const (
	MessageKindAll          MessageKind = "all"
	MessageKindNotification MessageKind = "notification"
	MessageKindAnnouncement MessageKind = "announcement"
)

type MessageReadState string

const (
	MessageReadAll    MessageReadState = "all"
	MessageReadOnly   MessageReadState = "read"
	MessageUnreadOnly MessageReadState = "unread"
)

type MessageCenterItem struct {
	Kind       MessageKind      `json:"kind"`
	ID         uuid.UUID        `json:"id"`
	Type       NotificationType `json:"type,omitempty"`
	Severity   string           `json:"severity"`
	Title      string           `json:"title"`
	Summary    string           `json:"summary,omitempty"`
	BodyHTML   string           `json:"body_html,omitempty"`
	LinkURL    string           `json:"link_url,omitempty"`
	OccurredAt time.Time        `json:"occurred_at"`
	Read       bool             `json:"read"`
	Pinned     bool             `json:"pinned,omitempty"`
}

type MessageCenterOptions struct {
	Page, PageSize int
	Kind           MessageKind
	Read           MessageReadState
	Severity       string
	Query          string
	From, To       *time.Time
}

func normalizeMessageCenterOptions(options MessageCenterOptions) (MessageCenterOptions, error) {
	p := models.NewPagination(options.Page, options.PageSize)
	options.Page, options.PageSize = p.Page, p.PageSize
	options.Query = strings.TrimSpace(options.Query)
	if err := validateText("message query", options.Query, 200, false); err != nil {
		return MessageCenterOptions{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if options.Kind == "" {
		options.Kind = MessageKindAll
	}
	if options.Kind != MessageKindAll && options.Kind != MessageKindNotification && options.Kind != MessageKindAnnouncement {
		return MessageCenterOptions{}, fmt.Errorf("%w: unsupported message kind", ErrInvalidInput)
	}
	if options.Read == "" {
		options.Read = MessageReadAll
	}
	if options.Read != MessageReadAll && options.Read != MessageReadOnly && options.Read != MessageUnreadOnly {
		return MessageCenterOptions{}, fmt.Errorf("%w: unsupported message read state", ErrInvalidInput)
	}
	if options.Severity != "" && options.Severity != SeverityInfo && options.Severity != SeverityWarning && options.Severity != SeverityCritical {
		return MessageCenterOptions{}, fmt.Errorf("%w: unsupported message severity", ErrInvalidInput)
	}
	if options.From != nil {
		value := options.From.UTC()
		options.From = &value
	}
	if options.To != nil {
		value := options.To.UTC()
		options.To = &value
	}
	if options.From != nil && options.To != nil && options.To.Before(*options.From) {
		return MessageCenterOptions{}, fmt.Errorf("%w: message end time precedes start time", ErrInvalidInput)
	}
	return options, nil
}

func (s *Store) CreateNotification(ctx context.Context, input NotificationInput) error {
	return createNotification(ctx, s.db, input)
}
func CreateNotificationTx(ctx context.Context, tx pgx.Tx, input NotificationInput) error {
	return createNotification(ctx, tx, input)
}
func createNotification(ctx context.Context, exec interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, input NotificationInput) error {
	if input.UserID == uuid.Nil || !input.Type.Valid() {
		return errors.New("valid notification user and type are required")
	}
	if input.Severity == "" {
		input.Severity = SeverityInfo
	}
	if input.Severity != SeverityInfo && input.Severity != SeverityWarning && input.Severity != SeverityCritical {
		return errors.New("notification severity is unsupported")
	}
	for _, f := range []struct {
		name, value string
		max         int
		required    bool
	}{{"notification title", input.Title, 160, true}, {"notification body", input.BodyMarkdown, 20000, true}} {
		if err := validateText(f.name, f.value, f.max, f.required); err != nil {
			return err
		}
	}
	if _, err := settings.RenderSiteBannerMarkdown(strings.TrimSpace(input.BodyMarkdown)); err != nil {
		return fmt.Errorf("notification body: %w", err)
	}
	if input.LinkURL != "" && !validLink(input.LinkURL) {
		return errors.New("notification link must use a root-relative path or absolute HTTPS URL")
	}
	if _, err := exec.Exec(ctx, `INSERT INTO user_notifications(user_id,notification_type,severity,title,body_markdown,link_url,source_type,source_id,dedupe_key,expires_at) VALUES($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),$10) ON CONFLICT (user_id,dedupe_key) WHERE dedupe_key IS NOT NULL DO NOTHING`, input.UserID, input.Type, input.Severity, strings.TrimSpace(input.Title), strings.TrimSpace(input.BodyMarkdown), input.LinkURL, input.SourceType, input.SourceID, input.DedupeKey, input.ExpiresAt); err != nil {
		return fmt.Errorf("creating user notification: %w", err)
	}
	return nil
}

const notificationColumns = `id,user_id,notification_type,severity,title,body_markdown,link_url,source_type,source_id,created_at,read_at,expires_at`

func scanNotification(row interface{ Scan(...any) error }) (*Notification, error) {
	n := &Notification{}
	var typ string
	var linkURL, sourceType, sourceID *string
	if err := row.Scan(&n.ID, &n.UserID, &typ, &n.Severity, &n.Title, &n.BodyMarkdown, &linkURL, &sourceType, &sourceID, &n.CreatedAt, &n.ReadAt, &n.ExpiresAt); err != nil {
		return nil, err
	}
	if linkURL != nil {
		n.LinkURL = *linkURL
	}
	if sourceType != nil {
		n.SourceType = *sourceType
	}
	if sourceID != nil {
		n.SourceID = *sourceID
	}
	n.Type = NotificationType(typ)
	n.BodyHTML, _ = settings.RenderSiteBannerMarkdown(n.BodyMarkdown)
	return n, nil
}

const messageCenterCTE = `
	WITH message_items AS (
		SELECT
			'notification'::text AS kind,
			n.id,
			n.notification_type::text AS item_type,
			n.severity::text AS severity,
			n.title,
			''::text AS summary,
			n.body_markdown,
			n.link_url,
			n.created_at AS occurred_at,
			(n.read_at IS NOT NULL) AS is_read,
			false AS pinned
		FROM user_notifications AS n
		WHERE n.user_id=$1 AND (n.expires_at IS NULL OR n.expires_at>NOW())
		UNION ALL
		SELECT
			'announcement'::text AS kind,
			a.id,
			''::text AS item_type,
			a.severity::text AS severity,
			a.title,
			a.summary,
			''::text AS body_markdown,
			a.link_url,
			GREATEST(a.updated_at,COALESCE(a.starts_at,a.updated_at)) AS occurred_at,
			EXISTS(
				SELECT 1 FROM announcement_reads AS ar
				WHERE ar.announcement_id=a.id AND ar.user_id=$1 AND ar.read_revision>=a.revision
			) AS is_read,
			a.pinned
		FROM announcements AS a
		WHERE a.status='published'
		  AND ($2::boolean OR a.audience='authenticated')
		  AND (a.starts_at IS NULL OR a.starts_at<=NOW())
		  AND (a.ends_at IS NULL OR a.ends_at>NOW())
	)
`

func (s *Store) ListMessageCenter(ctx context.Context, userID uuid.UUID, isAdmin bool, options MessageCenterOptions) (*models.PaginatedResponse[MessageCenterItem], error) {
	options, err := normalizeMessageCenterOptions(options)
	if err != nil {
		return nil, err
	}
	args := []any{userID, isAdmin}
	where := []string{"TRUE"}
	add := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if options.Kind != MessageKindAll {
		where = append(where, "kind="+add(string(options.Kind)))
	}
	if options.Read == MessageReadOnly {
		where = append(where, "is_read=TRUE")
	} else if options.Read == MessageUnreadOnly {
		where = append(where, "is_read=FALSE")
	}
	if options.Severity != "" {
		where = append(where, "severity="+add(options.Severity))
	}
	if options.Query != "" {
		pattern := add("%" + options.Query + "%")
		where = append(where, "(title ILIKE "+pattern+" OR summary ILIKE "+pattern+" OR body_markdown ILIKE "+pattern+")")
	}
	if options.From != nil {
		where = append(where, "occurred_at>="+add(*options.From))
	}
	if options.To != nil {
		where = append(where, "occurred_at<="+add(*options.To))
	}
	filter := strings.Join(where, " AND ")
	var total int64
	if err := s.db.QueryRow(ctx, messageCenterCTE+" SELECT COUNT(*) FROM message_items WHERE "+filter, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("counting message center items: %w", err)
	}
	limit := add(options.PageSize)
	offset := add((options.Page - 1) * options.PageSize)
	rows, err := s.db.Query(ctx, messageCenterCTE+`
		SELECT kind,id,item_type,severity,title,summary,body_markdown,link_url,occurred_at,is_read,pinned
		FROM message_items WHERE `+filter+`
		ORDER BY occurred_at DESC,id DESC LIMIT `+limit+` OFFSET `+offset, args...)
	if err != nil {
		return nil, fmt.Errorf("listing message center items: %w", err)
	}
	defer rows.Close()
	items := make([]MessageCenterItem, 0, options.PageSize)
	for rows.Next() {
		var item MessageCenterItem
		var kind, typ, bodyMarkdown string
		var linkURL *string
		if err := rows.Scan(&kind, &item.ID, &typ, &item.Severity, &item.Title, &item.Summary, &bodyMarkdown, &linkURL, &item.OccurredAt, &item.Read, &item.Pinned); err != nil {
			return nil, fmt.Errorf("scanning message center item: %w", err)
		}
		item.Kind = MessageKind(kind)
		item.Type = NotificationType(typ)
		if linkURL != nil {
			item.LinkURL = *linkURL
		}
		if item.Kind == MessageKindNotification {
			item.BodyHTML, _ = settings.RenderSiteBannerMarkdown(bodyMarkdown)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating message center items: %w", err)
	}
	return &models.PaginatedResponse[MessageCenterItem]{
		Items: items, Total: total, Page: options.Page, PageSize: options.PageSize,
		TotalPages: int((total + int64(options.PageSize) - 1) / int64(options.PageSize)),
	}, nil
}

func (s *Store) MarkAllMessagesRead(ctx context.Context, userID uuid.UUID, isAdmin bool, kind MessageKind) error {
	if kind == "" {
		kind = MessageKindAll
	}
	if kind != MessageKindAll && kind != MessageKindNotification && kind != MessageKindAnnouncement {
		return fmt.Errorf("%w: unsupported message kind", ErrInvalidInput)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting message read transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if kind == MessageKindAll || kind == MessageKindNotification {
		if _, err := tx.Exec(ctx, `UPDATE user_notifications SET read_at=NOW() WHERE user_id=$1 AND read_at IS NULL AND (expires_at IS NULL OR expires_at>NOW())`, userID); err != nil {
			return fmt.Errorf("marking notifications read: %w", err)
		}
	}
	if kind == MessageKindAll || kind == MessageKindAnnouncement {
		if _, err := tx.Exec(ctx, `
			INSERT INTO announcement_reads(announcement_id,user_id,read_revision)
			SELECT id,$1,revision FROM announcements
			WHERE status='published' AND ($2::boolean OR audience='authenticated')
			  AND (starts_at IS NULL OR starts_at<=NOW()) AND (ends_at IS NULL OR ends_at>NOW())
			ON CONFLICT (announcement_id,user_id) DO UPDATE
			SET read_revision=GREATEST(announcement_reads.read_revision,EXCLUDED.read_revision),read_at=NOW()
		`, userID, isAdmin); err != nil {
			return fmt.Errorf("marking announcements read: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing message read transaction: %w", err)
	}
	return nil
}

func (s *Store) ListNotifications(ctx context.Context, userID uuid.UUID, unreadOnly bool, page, pageSize int) (*models.PaginatedResponse[Notification], error) {
	p := models.NewPagination(page, pageSize)
	where := "user_id=$1 AND (expires_at IS NULL OR expires_at>NOW())"
	if unreadOnly {
		where += " AND read_at IS NULL"
	}
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT COUNT(*) FROM user_notifications WHERE "+where, userID).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, "SELECT "+notificationColumns+" FROM user_notifications WHERE "+where+" ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3", userID, p.PageSize, p.Offset())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Notification, 0, p.PageSize)
	for rows.Next() {
		n, e := scanNotification(rows)
		if e != nil {
			return nil, e
		}
		items = append(items, *n)
	}
	if e := rows.Err(); e != nil {
		return nil, e
	}
	return &models.PaginatedResponse[Notification]{Items: items, Total: total, Page: p.Page, PageSize: p.PageSize, TotalPages: int((total + int64(p.PageSize) - 1) / int64(p.PageSize))}, nil
}
func (s *Store) UnreadCount(ctx context.Context, userID uuid.UUID) (int64, error) {
	var count int64
	err := s.db.QueryRow(ctx, "SELECT COUNT(*) FROM user_notifications WHERE user_id=$1 AND read_at IS NULL AND (expires_at IS NULL OR expires_at>NOW())", userID).Scan(&count)
	return count, err
}
func (s *Store) MarkNotificationRead(ctx context.Context, id, userID uuid.UUID) error {
	_, err := s.db.Exec(ctx, "UPDATE user_notifications SET read_at=COALESCE(read_at,NOW()) WHERE id=$1 AND user_id=$2", id, userID)
	return err
}
func (s *Store) MarkAllNotificationsRead(ctx context.Context, userID uuid.UUID) error {
	_, err := s.db.Exec(ctx, "UPDATE user_notifications SET read_at=NOW() WHERE user_id=$1 AND read_at IS NULL", userID)
	return err
}
