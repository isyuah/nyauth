package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/pkg/models"
)

const maxHandlerBody = 1 << 20

type handlerService interface {
	List(ctx context.Context, page, pageSize int) (*models.PaginatedResponse[models.OAuthClient], error)
	CreateAdmin(ctx context.Context, req models.CreateClientRequest, mutation audit.MutationAudit) (*models.CreateClientResponse, error)
	GetByID(ctx context.Context, id string) (*models.OAuthClient, error)
	Update(ctx context.Context, id string, req models.UpdateClientRequest, mutation audit.MutationAudit) (*models.OAuthClient, error)
	UpdateOwner(ctx context.Context, id string, req models.UpdateClientOwnerRequest, mutation audit.MutationAudit) (*models.OAuthClient, error)
	Delete(ctx context.Context, id string, mutation audit.MutationAudit) error
	RotateSecret(ctx context.Context, id string, mutation audit.MutationAudit) (*models.RotateClientSecretResponse, error)
	ListAccessUsers(ctx context.Context, id string) ([]models.ClientAccessUser, error)
	ReplaceAccessUsers(ctx context.Context, id string, req models.ReplaceClientAccessUsersRequest, mutation audit.MutationAudit) ([]models.ClientAccessUser, error)
}

// Handler handles HTTP requests for client operations.
type Handler struct {
	service handlerService
}

// NewHandler creates a new client handler.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

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

// Routes returns a chi router with client routes.
func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Route("/{id}", func(r chi.Router) {
		r.Get("/", h.Get)
		r.Put("/", h.Update)
		r.Put("/owner", h.UpdateOwner)
		r.Delete("/", h.Delete)
		r.Post("/rotate-secret", h.RotateSecret)
	})
	return r
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))

	result, err := h.service.List(r.Context(), page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list clients")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req models.CreateClientRequest
	if err := decodeHandlerJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	result, err := h.service.CreateAdmin(r.Context(), req, mutation)
	if err != nil {
		switch {
		case IsInvalidClient(err):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, ErrClientQuotaExceeded):
			writeError(w, http.StatusConflict, "client quota exceeded")
		case errors.Is(err, ErrClientOwnerUnavailable):
			writeError(w, http.StatusConflict, "client owner is unavailable")
		default:
			writeError(w, http.StatusInternalServerError, "failed to create client")
		}
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	client, err := h.service.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "client not found")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to get client")
		}
		return
	}
	writeJSON(w, http.StatusOK, client)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req models.UpdateClientRequest
	if err := decodeHandlerJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}

	client, err := h.service.Update(r.Context(), id, req, mutation)
	if err != nil {
		switch {
		case IsInvalidClient(err):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, pgx.ErrNoRows):
			writeError(w, http.StatusNotFound, "client not found")
		default:
			writeError(w, http.StatusInternalServerError, "failed to update client")
		}
		return
	}
	writeJSON(w, http.StatusOK, client)
}

func (h *Handler) UpdateOwner(w http.ResponseWriter, r *http.Request) {
	var req models.UpdateClientOwnerRequest
	if err := decodeHandlerJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	updated, err := h.service.UpdateOwner(r.Context(), chi.URLParam(r, "id"), req, mutation)
	if err != nil {
		switch {
		case IsInvalidClient(err):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, pgx.ErrNoRows):
			writeError(w, http.StatusNotFound, "client not found")
		case errors.Is(err, ErrClientOwnerUnavailable):
			writeError(w, http.StatusConflict, "client owner is unavailable")
		case errors.Is(err, ErrClientQuotaExceeded):
			writeError(w, http.StatusConflict, "client quota exceeded")
		default:
			writeError(w, http.StatusInternalServerError, "failed to update client owner")
		}
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	if err := h.service.Delete(r.Context(), id, mutation); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "client not found")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to delete client")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RotateSecret(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	result, err := h.service.RotateSecret(r.Context(), chi.URLParam(r, "id"), mutation)
	if err != nil {
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			writeError(w, http.StatusNotFound, "client not found")
		case errors.Is(err, ErrPublicClientSecret):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to rotate client secret")
		}
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// ListAccessUsers returns the allowlisted users for a client.
func (h *Handler) ListAccessUsers(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	users, err := h.service.ListAccessUsers(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list access users")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

// ReplaceAccessUsers replaces the client's allowlist.
func (h *Handler) ReplaceAccessUsers(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req models.ReplaceClientAccessUsersRequest
	if err := decodeHandlerJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	users, err := h.service.ReplaceAccessUsers(r.Context(), id, req, mutation)
	if err != nil {
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			writeError(w, http.StatusNotFound, "client not found")
		case errors.Is(err, ErrAccessUserUnknown), errors.Is(err, ErrInvalidClient):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to update access users")
		}
		return
	}
	writeJSON(w, http.StatusOK, users)
}
