package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	announcementEventsPath      = "/api/announcement/events"
	announcementEventName       = "announcement"
	announcementKeepalive       = 10 * time.Second
	announcementRefreshInterval = time.Second
	maxAnnouncementEventStreams = 100
)

type communicationsSettingsResponse struct {
	Revision          int64                                         `json:"revision"`
	TemplateVariables map[string]account.EmailTemplateVariableRules `json:"template_variables"`
	settings.Communications
}

type updateCommunicationsSettingsRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
	settings.Communications
}

type emailTemplatePreviewRequest struct {
	TemplateID string                        `json:"template_id"`
	Email      account.EmailTemplateSettings `json:"email"`
}

type emailTemplateTestRequest struct {
	TemplateID string                        `json:"template_id"`
	Recipient  string                        `json:"recipient"`
	Email      account.EmailTemplateSettings `json:"email"`
}

type emailTemplatePreviewResponse struct {
	Subject  string `json:"subject"`
	TextBody string `json:"text_body"`
	HTMLBody string `json:"html_body"`
}

type publicAnnouncement struct {
	Version     int64      `json:"version"`
	Severity    string     `json:"severity"`
	Title       string     `json:"title"`
	Message     string     `json:"message"`
	LinkLabel   string     `json:"link_label,omitempty"`
	LinkURL     string     `json:"link_url,omitempty"`
	Dismissible bool       `json:"dismissible"`
	EndsAt      *time.Time `json:"ends_at,omitempty"`
}

type publicAnnouncementResponse struct {
	Announcement *publicAnnouncement `json:"announcement"`
	NextChangeAt *time.Time          `json:"next_change_at,omitempty"`
}

func (s *Server) handleGetCommunicationsSettings(w http.ResponseWriter, _ *http.Request) {
	snapshot := s.settingsMgr.CommunicationsSnapshot()
	writeJSON(w, http.StatusOK, communicationsSettingsResponse{
		Revision: snapshot.Revision, Communications: snapshot.Value,
		TemplateVariables: emailTemplateVariables(),
	})
}

func (s *Server) handleUpdateCommunicationsSettings(w http.ResponseWriter, r *http.Request) {
	currentUser, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request updateCommunicationsSettingsRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	value, err := settings.NormalizeCommunications(request.Communications)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	revision, value, err := s.settingsMgr.SetCommunications(
		r.Context(), value, request.ExpectedRevision, currentUser.Username, mutation,
	)
	if err != nil {
		if errors.Is(err, settings.ErrRevisionConflict) {
			writeAPIError(w, http.StatusConflict, "settings revision conflict")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "failed to store communication settings")
		return
	}
	writeJSON(w, http.StatusOK, communicationsSettingsResponse{
		Revision: revision, Communications: value, TemplateVariables: emailTemplateVariables(),
	})
}

func (s *Server) handlePreviewEmailTemplate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request emailTemplatePreviewRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	message, err := s.renderEmailTemplateDraft(request.TemplateID, request.Email, "preview@example.invalid")
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, emailTemplatePreviewResponse{
		Subject: message.Subject, TextBody: message.TextBody, HTMLBody: message.HTMLBody,
	})
}

func (s *Server) handleTestEmailTemplate(w http.ResponseWriter, r *http.Request) {
	mutation, ok := s.authorizeMailMutation(w, r, mailSettingsActionCandidateTest)
	if !ok {
		return
	}
	var request emailTemplateTestRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	recipient, err := normalizeMailTestRecipient(request.Recipient)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	currentUser := currentUserFromContext(r)
	if currentUser == nil || currentUser.Email == nil || currentUser.EmailVerifiedAt == nil {
		writeAPIError(w, http.StatusConflict, "a verified administrator email is required for template tests")
		return
	}
	verifiedRecipient, err := normalizeMailTestRecipient(*currentUser.Email)
	if err != nil || !strings.EqualFold(recipient, verifiedRecipient) {
		writeAPIError(w, http.StatusBadRequest, "test recipient must match the administrator's verified email")
		return
	}
	message, err := s.renderEmailTemplateDraft(request.TemplateID, request.Email, recipient)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	message.Subject = "[TEST] " + message.Subject
	if s.mailManager == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "mail delivery is unavailable")
		return
	}
	sender, _, available := s.mailManager.CurrentSender()
	if !available || sender == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "mail delivery is unavailable")
		return
	}
	if err := sender.Send(r.Context(), message); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "test email could not be delivered")
		return
	}
	s.enqueueAuditTargetResult(
		r.Context(), models.AuditMailTemplateTested, &mutation.ActorID, mutation.ActorName,
		"email_template", strings.TrimSpace(request.TemplateID), "success", "high",
		mutation.IPAddress, mutation.UserAgent, map[string]any{"draft": true},
	)
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (s *Server) renderEmailTemplateDraft(templateID string, draft account.EmailTemplateSettings, recipient string) (account.EmailMessage, error) {
	draft, err := account.NormalizeEmailTemplateSettings(draft)
	if err != nil {
		return account.EmailMessage{}, err
	}
	return account.RenderEmailTemplate(strings.TrimSpace(templateID), recipient, account.EmailPresentation{
		SiteName: s.settingsMgr.Branding().Title, Settings: draft,
	}, sampleEmailRenderData())
}

func sampleEmailRenderData() account.EmailRenderData {
	return account.EmailRenderData{
		Username: "示例用户", TTL: "30 分钟", Role: "admin", Status: "active", Provider: "github",
		ActionURL: "https://example.invalid/account-action?token=preview-only",
	}
}

func emailTemplateVariables() map[string]account.EmailTemplateVariableRules {
	result := make(map[string]account.EmailTemplateVariableRules)
	for _, id := range account.EmailTemplateIDs() {
		result[id] = account.EmailTemplateVariables(id)
	}
	return result
}

func (s *Server) handleAnnouncement(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.currentPublicAnnouncement(time.Now().UTC()))
}

func (s *Server) currentPublicAnnouncement(now time.Time) publicAnnouncementResponse {
	return publicAnnouncementAt(s.settingsMgr.Communications().Announcement, now)
}

func publicAnnouncementAt(value settings.Announcement, now time.Time) publicAnnouncementResponse {
	response := publicAnnouncementResponse{}
	if value.Enabled && value.StartsAt != nil && now.Before(*value.StartsAt) {
		start := value.StartsAt.UTC()
		response.NextChangeAt = &start
	}
	if !settings.AnnouncementActiveAt(value, now) {
		return response
	}
	response.Announcement = &publicAnnouncement{
		Version: value.Version, Severity: value.Severity, Title: value.Title, Message: value.Message,
		LinkLabel: value.LinkLabel, LinkURL: value.LinkURL, Dismissible: value.Dismissible, EndsAt: value.EndsAt,
	}
	if value.EndsAt != nil {
		end := value.EndsAt.UTC()
		response.NextChangeAt = &end
	}
	return response
}

func (s *Server) handleAnnouncementEvents(w http.ResponseWriter, r *http.Request) {
	if !s.claimAnnouncementStream() {
		w.Header().Set("Retry-After", "30")
		writeAPIError(w, http.StatusTooManyRequests, "too many announcement streams")
		return
	}
	defer s.announcementStreams.Add(-1)
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "streaming is unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	lastPayload := ""
	send := func() error {
		encoded, err := json.Marshal(s.currentPublicAnnouncement(time.Now().UTC()))
		if err != nil {
			return err
		}
		payload := string(encoded)
		if payload == lastPayload {
			return nil
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", announcementEventName, payload); err != nil {
			return err
		}
		lastPayload = payload
		flusher.Flush()
		return nil
	}
	if err := send(); err != nil {
		return
	}
	refresh := time.NewTicker(announcementRefreshInterval)
	keepalive := time.NewTicker(announcementKeepalive)
	defer refresh.Stop()
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-refresh.C:
			if err := send(); err != nil {
				return
			}
		case <-keepalive.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) claimAnnouncementStream() bool {
	for {
		current := s.announcementStreams.Load()
		if current >= maxAnnouncementEventStreams {
			return false
		}
		if s.announcementStreams.CompareAndSwap(current, current+1) {
			return true
		}
	}
}
