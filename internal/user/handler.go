package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/pkg/models"
)

const maxHandlerBody = 1 << 20

func decodeHandlerJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxHandlerBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request body must contain one JSON value")
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

type handlerService interface {
	List(ctx context.Context, page, pageSize int, search string, status models.UserStatus) (*models.PaginatedResponse[models.User], error)
	Create(ctx context.Context, req models.CreateUserRequest) (*models.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	AdminUpdate(ctx context.Context, id uuid.UUID, req models.AdminUpdateUserRequest, mutation audit.MutationAudit) (*models.User, error)
	Delete(ctx context.Context, id uuid.UUID, mutation audit.MutationAudit) error
	ResetPassword(ctx context.Context, id uuid.UUID, newPassword string, mutation audit.MutationAudit) (*models.User, error)
}

// Handler handles HTTP requests for user operations.
type Handler struct {
	service handlerService
}

// NewHandler creates a new user handler.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// Routes returns a chi router with user routes mounted.
func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Route("/{id}", func(r chi.Router) {
		r.Get("/", h.Get)
		r.Put("/", h.Update)
		r.Delete("/", h.Delete)
		r.Post("/reset-password", h.ResetPassword)
	})
	return r
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	search := r.URL.Query().Get("q")
	status := models.UserStatus(r.URL.Query().Get("status"))
	if status != "" && status != models.UserStatusActive && status != models.UserStatusSuspended && status != models.UserStatusPending {
		writeError(w, http.StatusBadRequest, "invalid user status")
		return
	}

	result, err := h.service.List(r.Context(), page, pageSize, search, status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req models.CreateUserRequest
	if err := decodeHandlerJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.service.Create(r.Context(), req)
	if err != nil {
		if IsInvalidInput(err) {
			writeError(w, http.StatusBadRequest, err.Error())
		} else if isUniqueViolation(err) {
			writeError(w, http.StatusConflict, "username or email already exists")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to create user")
		}
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	user, err := h.service.GetByID(r.Context(), id)
	if err != nil {
		if IsNotFound(err) {
			writeError(w, http.StatusNotFound, "user not found")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to get user")
		}
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	var req models.AdminUpdateUserRequest
	if err := decodeHandlerJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	user, err := h.service.AdminUpdate(r.Context(), id, req, mutation)
	if err != nil {
		if errors.Is(err, ErrLastActiveAdmin) {
			writeError(w, http.StatusConflict, err.Error())
		} else if IsInvalidInput(err) {
			writeError(w, http.StatusBadRequest, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, "failed to update user")
		}
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	if err := h.service.Delete(r.Context(), id, mutation); err != nil {
		if errors.Is(err, ErrLastActiveAdmin) {
			writeError(w, http.StatusConflict, err.Error())
		} else if IsNotFound(err) {
			writeError(w, http.StatusNotFound, "user not found")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to delete user")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := decodeHandlerJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	if _, err := h.service.ResetPassword(r.Context(), id, body.Password, mutation); err != nil {
		if IsInvalidInput(err) {
			writeError(w, http.StatusBadRequest, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, "failed to reset password")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes an error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
