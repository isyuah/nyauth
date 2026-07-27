package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/buildinfo"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	defaultAuditExportLimit = 10_000
	maximumAuditExportLimit = 50_000
	maximumAuditExportRange = 31 * 24 * time.Hour
)

func (s *Server) handleExportAuditLogs(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "ndjson"
	}
	if format != "ndjson" && format != "cef" {
		writeAPIError(w, http.StatusBadRequest, "format must be ndjson or cef")
		return
	}
	limit := defaultAuditExportLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maximumAuditExportLimit {
			writeAPIError(w, http.StatusBadRequest, "limit must be between 1 and 50000")
			return
		}
		limit = parsed
	}
	filter, err := auditExportFilter(r, time.Now().UTC())
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	if format == "cef" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="nyauth-audit-`+timestamp+`.cef"`)
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="nyauth-audit-`+timestamp+`.ndjson"`)
	}

	started := false
	encoder := json.NewEncoder(w)
	_, err = s.auditStore.Stream(r.Context(), filter, limit, func(entry models.AuditLog) error {
		started = true
		if format == "cef" {
			_, writeErr := fmt.Fprintln(w, auditLogCEF(entry))
			return writeErr
		}
		return encoder.Encode(adminAuditLogFromModel(entry))
	})
	if err == nil {
		return
	}
	if !started {
		writeAPIError(w, http.StatusInternalServerError, "failed to export audit logs")
		return
	}
	slog.ErrorContext(r.Context(), "audit export stream failed", "format", format, "error", err)
}

func auditExportFilter(r *http.Request, now time.Time) (audit.ListFilter, error) {
	filter, err := auditLogFilterFromRequest(r)
	if err != nil {
		return filter, err
	}
	to := now.UTC()
	if filter.CreatedTo != nil {
		to = filter.CreatedTo.UTC()
	}
	from := to.Add(-24 * time.Hour)
	if filter.CreatedFrom != nil {
		from = filter.CreatedFrom.UTC()
	}
	if !to.After(from) {
		return filter, fmt.Errorf("to must be later than from")
	}
	if to.Sub(from) > maximumAuditExportRange {
		return filter, fmt.Errorf("audit export range must not exceed 31 days")
	}
	filter.CreatedFrom = &from
	filter.CreatedTo = &to
	return filter, nil
}

func auditLogCEF(entry models.AuditLog) string {
	severity := 3
	switch entry.RiskLevel {
	case "medium":
		severity = 5
	case "high":
		severity = 8
	case "critical":
		severity = 10
	}
	extension := []string{
		"rt=" + strconv.FormatInt(entry.CreatedAt.UTC().UnixMilli(), 10),
		"outcome=" + cefExtensionValue(entry.Result),
		"cs1Label=Risk",
		"cs1=" + cefExtensionValue(entry.RiskLevel),
		"externalId=" + cefExtensionValue(entry.ID.String()),
	}
	if entry.ActorName != nil {
		extension = append(extension, "suser="+cefExtensionValue(*entry.ActorName))
	} else if entry.ActorID != nil {
		extension = append(extension, "suser="+cefExtensionValue(entry.ActorID.String()))
	}
	if entry.IPAddress != nil {
		extension = append(extension, "src="+cefExtensionValue(*entry.IPAddress))
	}
	if entry.TargetID != nil {
		target := *entry.TargetID
		if entry.TargetType != nil {
			target = *entry.TargetType + ":" + target
		}
		extension = append(extension, "duser="+cefExtensionValue(target))
	}
	return fmt.Sprintf(
		"CEF:0|Nyauth|Nyauth|%s|%s|%s|%d|%s",
		cefHeaderValue(buildinfo.Version), cefHeaderValue(entry.Event), cefHeaderValue(entry.Event), severity, strings.Join(extension, " "),
	)
}

func cefHeaderValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, "|", `\|`)
}

func cefExtensionValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "=", `\=`)
	value = strings.ReplaceAll(value, "\r", `\r`)
	return strings.ReplaceAll(value, "\n", `\n`)
}
