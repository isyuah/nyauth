package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

const instrumentationName = "github.com/nyasharp/nyauth/internal/telemetry"

// Runtime owns the process metric provider and low-cardinality application
// instruments. It intentionally does not attach user, client, token, IP, or
// other unbounded identifiers to metrics.
type Runtime struct {
	provider             *sdkmetric.MeterProvider
	meter                metric.Meter
	httpRequests         metric.Int64Counter
	httpDuration         metric.Float64Histogram
	authEvents           metric.Int64Counter
	dependencyDuration   metric.Float64Histogram
	auditFailures        metric.Int64Counter
	csrfRejections       metric.Int64Counter
	oauthGrants          metric.Int64Counter
	refreshReuse         metric.Int64Counter
	providerEvents       metric.Int64Counter
	jwkRotations         metric.Int64Counter
	rateLimitEvents      metric.Int64Counter
	registrationEvents   metric.Int64Counter
	verificationTime     metric.Float64Histogram
	smtpDeliveries       metric.Int64Counter
	smtpRetries          metric.Int64Counter
	smtpFailures         metric.Int64Counter
	smtpBacklog          metric.Int64Gauge
	smtpOldestAge        metric.Float64Gauge
	smtpCircuitOpen      metric.Int64Gauge
	avatarOperations     metric.Int64Counter
	avatarDuration       metric.Float64Histogram
	avatarStorageErrors  metric.Int64Counter
	avatarCleanupPending metric.Int64Gauge
	postgresPool         metric.Int64ObservableGauge
	redisPool            metric.Int64ObservableGauge
	registrationMu       sync.Mutex
	registrations        []metric.Registration
}

type Options struct {
	OTLPEnabled        bool
	OTLPEndpoint       string
	OTLPAuthorization  string
	OTLPExportInterval time.Duration
	OTLPTimeout        time.Duration
}

func New(ctx context.Context, options Options) (*Runtime, error) {
	exporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("creating Prometheus exporter: %w", err)
	}
	providerOptions := []sdkmetric.Option{sdkmetric.WithReader(exporter)}
	if options.OTLPEnabled {
		if options.OTLPEndpoint == "" {
			return nil, fmt.Errorf("OTLP endpoint is required when the exporter is enabled")
		}
		if options.OTLPExportInterval <= 0 || options.OTLPTimeout <= 0 {
			return nil, fmt.Errorf("OTLP export interval and timeout must be positive")
		}
		exporterOptions := []otlpmetrichttp.Option{
			otlpmetrichttp.WithEndpointURL(options.OTLPEndpoint),
			otlpmetrichttp.WithTimeout(options.OTLPTimeout),
		}
		if options.OTLPAuthorization != "" {
			exporterOptions = append(exporterOptions, otlpmetrichttp.WithHeaders(map[string]string{
				"Authorization": options.OTLPAuthorization,
			}))
		}
		otlpExporter, err := otlpmetrichttp.New(ctx, exporterOptions...)
		if err != nil {
			return nil, fmt.Errorf("creating OTLP metrics exporter: %w", err)
		}
		providerOptions = append(providerOptions, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(
			otlpExporter,
			sdkmetric.WithInterval(options.OTLPExportInterval),
			sdkmetric.WithTimeout(options.OTLPTimeout),
		)))
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
			slog.Error("OTLP metric export failed", "error", err)
		}))
	}
	provider := sdkmetric.NewMeterProvider(providerOptions...)
	otel.SetMeterProvider(provider)
	meter := provider.Meter(instrumentationName)

	httpRequests, err := meter.Int64Counter("nyauth.http.server.requests", metric.WithDescription("HTTP requests handled by route and status class"))
	if err != nil {
		return nil, err
	}
	httpDuration, err := meter.Float64Histogram("nyauth.http.server.duration", metric.WithUnit("s"), metric.WithDescription("HTTP request duration"))
	if err != nil {
		return nil, err
	}
	authEvents, err := meter.Int64Counter("nyauth.auth.events", metric.WithDescription("Authentication and OAuth security events"))
	if err != nil {
		return nil, err
	}
	dependencyDuration, err := meter.Float64Histogram("nyauth.dependency.duration", metric.WithUnit("s"), metric.WithDescription("Database, Redis, SMTP, and provider operation duration"))
	if err != nil {
		return nil, err
	}
	auditFailures, err := meter.Int64Counter("nyauth.audit.write_failures", metric.WithDescription("Audit events that could not be persisted"))
	if err != nil {
		return nil, err
	}
	csrfRejections, err := meter.Int64Counter("nyauth.security.csrf.rejections", metric.WithDescription("First-party API requests rejected by CSRF validation"))
	if err != nil {
		return nil, err
	}
	oauthGrants, err := meter.Int64Counter("nyauth.oauth.grants", metric.WithDescription("OAuth token grant outcomes by supported grant type and bounded reason"))
	if err != nil {
		return nil, err
	}
	refreshReuse, err := meter.Int64Counter("nyauth.oauth.refresh_token.reuse", metric.WithDescription("Detected refresh-token reuse events"))
	if err != nil {
		return nil, err
	}
	providerEvents, err := meter.Int64Counter("nyauth.provider.events", metric.WithDescription("External provider callback, authentication, synchronization, and validation outcomes"))
	if err != nil {
		return nil, err
	}
	jwkRotations, err := meter.Int64Counter("nyauth.jwk.rotations", metric.WithDescription("JWK signing-key lifecycle outcomes"))
	if err != nil {
		return nil, err
	}
	rateLimitEvents, err := meter.Int64Counter("nyauth.rate_limit.events", metric.WithDescription("Rate-limit decisions by bounded limiter and action"))
	if err != nil {
		return nil, err
	}
	registrationEvents, err := meter.Int64Counter("nyauth.registration.outcomes", metric.WithDescription("Self-registration outcomes by bounded result and reason"))
	if err != nil {
		return nil, err
	}
	verificationTime, err := meter.Float64Histogram("nyauth.registration.verification.duration", metric.WithUnit("s"), metric.WithDescription("Time from pending self-registration creation to email verification"))
	if err != nil {
		return nil, err
	}
	smtpDeliveries, err := meter.Int64Counter("nyauth.smtp.outbox.deliveries", metric.WithDescription("Email outbox delivery outcomes"))
	if err != nil {
		return nil, err
	}
	smtpRetries, err := meter.Int64Counter("nyauth.smtp.outbox.retries", metric.WithDescription("Email outbox retries successfully scheduled"))
	if err != nil {
		return nil, err
	}
	smtpFailures, err := meter.Int64Counter("nyauth.smtp.outbox.failures", metric.WithDescription("SMTP failures by bounded error category"))
	if err != nil {
		return nil, err
	}
	smtpBacklog, err := meter.Int64Gauge("nyauth.smtp.outbox.backlog", metric.WithDescription("Last observed number of deliverable or in-flight email outbox entries"))
	if err != nil {
		return nil, err
	}
	smtpOldestAge, err := meter.Float64Gauge("nyauth.smtp.outbox.oldest_pending_age", metric.WithUnit("s"), metric.WithDescription("Age of the oldest deliverable or in-flight email outbox entry"))
	if err != nil {
		return nil, err
	}
	smtpCircuitOpen, err := meter.Int64Gauge("nyauth.smtp.circuit.open", metric.WithDescription("SMTP circuit state, where closed is 0 and open is 1"))
	if err != nil {
		return nil, err
	}
	avatarOperations, err := meter.Int64Counter("nyauth.avatar.operations", metric.WithDescription("Avatar media operations by bounded outcome and reason"))
	if err != nil {
		return nil, err
	}
	avatarDuration, err := meter.Float64Histogram("nyauth.avatar.processing.duration", metric.WithUnit("s"), metric.WithDescription("Avatar upload and provider-import processing duration"))
	if err != nil {
		return nil, err
	}
	avatarStorageErrors, err := meter.Int64Counter("nyauth.avatar.storage.errors", metric.WithDescription("Avatar storage failures by backend and operation"))
	if err != nil {
		return nil, err
	}
	avatarCleanupPending, err := meter.Int64Gauge("nyauth.avatar.cleanup.pending", metric.WithDescription("Avatar records awaiting object cleanup for the configured backend"))
	if err != nil {
		return nil, err
	}
	postgresPool, err := meter.Int64ObservableGauge("nyauth.postgresql.pool.connections", metric.WithDescription("PostgreSQL pool connections by bounded state"))
	if err != nil {
		return nil, err
	}
	redisPool, err := meter.Int64ObservableGauge("nyauth.redis.pool.connections", metric.WithDescription("Redis pool connections by bounded state"))
	if err != nil {
		return nil, err
	}

	return &Runtime{
		provider: provider, meter: meter, httpRequests: httpRequests, httpDuration: httpDuration,
		authEvents: authEvents, dependencyDuration: dependencyDuration, auditFailures: auditFailures,
		csrfRejections: csrfRejections, oauthGrants: oauthGrants, refreshReuse: refreshReuse,
		providerEvents: providerEvents, jwkRotations: jwkRotations, rateLimitEvents: rateLimitEvents,
		registrationEvents: registrationEvents, verificationTime: verificationTime,
		smtpDeliveries: smtpDeliveries, smtpRetries: smtpRetries, smtpFailures: smtpFailures,
		smtpBacklog: smtpBacklog, smtpOldestAge: smtpOldestAge, smtpCircuitOpen: smtpCircuitOpen,
		avatarOperations: avatarOperations, avatarDuration: avatarDuration, avatarStorageErrors: avatarStorageErrors,
		avatarCleanupPending: avatarCleanupPending,
		postgresPool:         postgresPool, redisPool: redisPool,
	}, nil
}

func (r *Runtime) Shutdown(ctx context.Context) error {
	if r == nil || r.provider == nil {
		return nil
	}
	r.registrationMu.Lock()
	for _, registration := range r.registrations {
		_ = registration.Unregister()
	}
	r.registrations = nil
	r.registrationMu.Unlock()
	return r.provider.Shutdown(ctx)
}

// BindPoolObservers exports local pool state without querying PostgreSQL or
// Redis. It is safe to omit either dependency in focused tests.
func (r *Runtime) BindPoolObservers(db *pgxpool.Pool, rdb *redis.Client) error {
	if r == nil || r.meter == nil || (db == nil && rdb == nil) {
		return nil
	}
	observables := make([]metric.Observable, 0, 2)
	if db != nil {
		observables = append(observables, r.postgresPool)
	}
	if rdb != nil {
		observables = append(observables, r.redisPool)
	}
	registration, err := r.meter.RegisterCallback(func(ctx context.Context, observer metric.Observer) error {
		if db != nil {
			stats := db.Stat()
			for state, value := range map[string]int64{
				"acquired":     int64(stats.AcquiredConns()),
				"constructing": int64(stats.ConstructingConns()),
				"idle":         int64(stats.IdleConns()),
				"maximum":      int64(stats.MaxConns()),
				"total":        int64(stats.TotalConns()),
			} {
				observer.ObserveInt64(r.postgresPool, value, metric.WithAttributes(attribute.String("pool.state", state)))
			}
		}
		if rdb != nil {
			stats := rdb.PoolStats()
			for state, value := range map[string]int64{
				"idle":  int64(stats.IdleConns),
				"stale": int64(stats.StaleConns),
				"total": int64(stats.TotalConns),
			} {
				observer.ObserveInt64(r.redisPool, value, metric.WithAttributes(attribute.String("pool.state", state)))
			}
		}
		return nil
	}, observables...)
	if err != nil {
		return fmt.Errorf("registering dependency pool metrics: %w", err)
	}
	r.registrationMu.Lock()
	r.registrations = append(r.registrations, registration)
	r.registrationMu.Unlock()
	return nil
}

// PrometheusHandler is intended for an internal-only listener or route. The
// production reverse proxy must not expose it to the public Internet.
func (r *Runtime) PrometheusHandler() http.Handler { return promhttp.Handler() }

func (r *Runtime) HTTPMiddleware(next http.Handler) http.Handler {
	traced := otelhttp.NewMiddleware("nyauth.http")(next)
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		started := time.Now()
		wrapped := chimiddleware.NewWrapResponseWriter(w, request.ProtoMajor)
		traced.ServeHTTP(wrapped, request)
		status := wrapped.Status()
		if status == 0 {
			status = http.StatusOK
		}
		route := "unmatched"
		if routeContext := chi.RouteContext(request.Context()); routeContext != nil && routeContext.RoutePattern() != "" {
			route = routeContext.RoutePattern()
		}
		attributes := []attribute.KeyValue{
			attribute.String("http.request.method", boundedHTTPMethod(request.Method)),
			attribute.String("http.route", route),
			attribute.String("http.response.status_class", strconv.Itoa(status/100)+"xx"),
		}
		r.httpRequests.Add(request.Context(), 1, metric.WithAttributes(attributes...))
		r.httpDuration.Record(request.Context(), time.Since(started).Seconds(), metric.WithAttributes(attributes...))
	})
}

func (r *Runtime) RecordAuthEvent(ctx context.Context, operation, result string) {
	if r == nil {
		return
	}
	r.authEvents.Add(ctx, 1, metric.WithAttributes(
		attribute.String("auth.operation", operation),
		attribute.String("auth.result", result),
	))
}

func (r *Runtime) RecordDependency(ctx context.Context, dependency, operation, result string, duration time.Duration) {
	if r == nil {
		return
	}
	r.dependencyDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
		attribute.String("dependency.name", dependency),
		attribute.String("dependency.operation", operation),
		attribute.String("dependency.result", result),
	))
}

func (r *Runtime) RecordAuditFailure(ctx context.Context, event string) {
	if r == nil {
		return
	}
	r.auditFailures.Add(ctx, 1, metric.WithAttributes(attribute.String("audit.event", event)))
}

func (r *Runtime) RecordCSRFReject(ctx context.Context, reason string) {
	if r == nil {
		return
	}
	reason = boundedValue(reason, "other", "missing_session", "missing_token", "mismatch")
	r.csrfRejections.Add(ctx, 1, metric.WithAttributes(attribute.String("csrf.reason", reason)))
}

func (r *Runtime) RecordOAuthGrant(ctx context.Context, grantType, result, reason string) {
	if r == nil {
		return
	}
	grantType = boundedValue(grantType, "unsupported", "authorization_code", "client_credentials", "refresh_token", "unsupported")
	result = boundedValue(result, "failure", "success", "failure")
	reason = boundedValue(reason, "other",
		"none", "invalid_form", "unsupported_grant_type", "invalid_request", "invalid_or_expired_code",
		"invalid_client", "code_binding_validation", "scope_no_longer_allowed", "invalid_subject",
		"inactive_subject", "code_reuse", "authorization_inactive", "token_issuance_failed",
		"id_token_issuance_failed", "grant_not_allowed", "invalid_scope", "refresh_reuse", "invalid_refresh",
	)
	r.oauthGrants.Add(ctx, 1, metric.WithAttributes(
		attribute.String("oauth.grant_type", grantType),
		attribute.String("oauth.result", result),
		attribute.String("oauth.reason", reason),
	))
	if reason == "refresh_reuse" {
		r.refreshReuse.Add(ctx, 1)
	}
}

func (r *Runtime) RecordProviderEvent(ctx context.Context, operation, intent, result, reason string, duration time.Duration) {
	if r == nil {
		return
	}
	operation = boundedValue(operation, "other", "callback", "authentication", "synchronization", "validation")
	intent = boundedValue(intent, "none", "none", "login", "bind", "reauth")
	result = boundedValue(result, "failure", "success", "failure")
	reason = boundedValue(reason, "other",
		"none", "invalid_state", "provider_denied", "missing_code", "provider_unavailable",
		"provider_authentication_failed", "session_changed", "identity_already_bound", "binding_failed",
		"identity_mismatch", "reauthentication_failed", "session_failed", "account_unavailable",
		"load_failed", "database_unavailable", "not_found", "decrypt_failed", "configuration_invalid",
		"endpoint_invalid", "listener_connect_failed", "listener_subscribe_failed", "listener_disconnected",
		"notification_publish_failed",
	)
	attributes := []attribute.KeyValue{
		attribute.String("provider.operation", operation),
		attribute.String("provider.intent", intent),
		attribute.String("provider.result", result),
		attribute.String("provider.reason", reason),
	}
	r.providerEvents.Add(ctx, 1, metric.WithAttributes(attributes...))
	if duration >= 0 {
		r.dependencyDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
			attribute.String("dependency.name", "provider"),
			attribute.String("dependency.operation", operation),
			attribute.String("dependency.result", result),
		))
	}
}

func (r *Runtime) RecordJWKRotation(ctx context.Context, trigger, result, reason string, duration time.Duration) {
	if r == nil {
		return
	}
	trigger = boundedValue(trigger, "other", "startup", "scheduled", "manual")
	result = boundedValue(result, "failure", "success", "failure")
	reason = boundedValue(reason, "other", "none", "rotation_failed", "initialization_failed")
	r.jwkRotations.Add(ctx, 1, metric.WithAttributes(
		attribute.String("jwk.trigger", trigger),
		attribute.String("jwk.result", result),
		attribute.String("jwk.reason", reason),
	))
	if duration >= 0 {
		r.dependencyDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
			attribute.String("dependency.name", "jwk"),
			attribute.String("dependency.operation", "rotation"),
			attribute.String("dependency.result", result),
		))
	}
}

func (r *Runtime) RecordRateLimit(ctx context.Context, limiter, action, result string) {
	if r == nil {
		return
	}
	limiter = boundedValue(limiter, "other", "login", "account_action", "avatar")
	action = boundedValue(action, "other", "login", "register", "password_reset", "email_verification", "pending_email_verification", "email_change", "upload", "delete")
	result = boundedValue(result, "error", "allowed", "rejected", "error")
	r.rateLimitEvents.Add(ctx, 1, metric.WithAttributes(
		attribute.String("rate_limit.limiter", limiter),
		attribute.String("rate_limit.action", action),
		attribute.String("rate_limit.result", result),
	))
}

func (r *Runtime) RecordRegistrationOutcome(ctx context.Context, result, reason string) {
	if r == nil {
		return
	}
	result = boundedValue(result, "failure", "success", "rejected", "failure")
	reason = boundedValue(reason, "dependency_unavailable",
		"registered", "pending_verification", "closed", "invalid_origin", "invalid_input",
		"invalid_invite", "conflict", "rate_limited", "mail_unavailable", "dependency_unavailable",
	)
	r.registrationEvents.Add(ctx, 1, metric.WithAttributes(
		attribute.String("registration.result", result),
		attribute.String("registration.reason", reason),
	))
}

func (r *Runtime) RecordEmailVerificationDuration(ctx context.Context, duration time.Duration) {
	if r == nil || duration < 0 {
		return
	}
	r.verificationTime.Record(ctx, duration.Seconds())
}

func (r *Runtime) RecordSMTPDelivery(ctx context.Context, result string, retryScheduled bool) {
	if r == nil {
		return
	}
	result = boundedValue(result, "failure", "success", "failure")
	r.smtpDeliveries.Add(ctx, 1, metric.WithAttributes(attribute.String("smtp.result", result)))
	if retryScheduled {
		r.smtpRetries.Add(ctx, 1)
	}
}

func (r *Runtime) RecordSMTPError(ctx context.Context, category string) {
	if r == nil {
		return
	}
	category = boundedValue(category, "unknown", "configuration", "authentication", "tls", "transport", "recipient", "unknown")
	r.smtpFailures.Add(ctx, 1, metric.WithAttributes(attribute.String("smtp.error_category", category)))
}

func (r *Runtime) RecordSMTPCircuitState(ctx context.Context, state string) {
	if r == nil {
		return
	}
	switch state {
	case "closed":
		r.smtpCircuitOpen.Record(ctx, 0)
	case "open":
		r.smtpCircuitOpen.Record(ctx, 1)
	}
}

func (r *Runtime) RecordSMTPBacklog(ctx context.Context, backlog int64, oldestAge time.Duration) {
	if r == nil {
		return
	}
	if backlog < 0 {
		backlog = 0
	}
	if oldestAge < 0 {
		oldestAge = 0
	}
	r.smtpBacklog.Record(ctx, backlog)
	r.smtpOldestAge.Record(ctx, oldestAge.Seconds())
}

func (r *Runtime) RecordAvatarOperation(ctx context.Context, operation, result, reason string, duration time.Duration) {
	if r == nil {
		return
	}
	operation = boundedValue(operation, "other", "upload", "delete", "read", "provider_import", "cleanup")
	result = boundedValue(result, "failure", "success", "failure", "rejected", "discarded", "retry")
	reason = boundedValue(reason, "other",
		"none", "too_large", "unsupported_media", "animated", "invalid_dimensions", "not_square",
		"rate_limited", "dependency_unavailable", "not_found", "avatar_already_set", "policy_disabled",
		"decryption_failed", "invalid_url", "invalid_port", "host_not_allowed", "unsafe_address",
		"too_many_redirects", "invalid_redirect", "remote_rejected", "remote_too_large", "invalid_image",
		"remote_or_storage_unavailable", "storage_unavailable", "canceled",
		"cleanup_deferred", "processor_busy",
	)
	attributes := []attribute.KeyValue{
		attribute.String("avatar.operation", operation),
		attribute.String("avatar.result", result),
		attribute.String("avatar.reason", reason),
	}
	r.avatarOperations.Add(ctx, 1, metric.WithAttributes(attributes...))
	if duration >= 0 && (operation == "upload" || operation == "provider_import") {
		r.avatarDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attributes...))
	}
}

func (r *Runtime) RecordAvatarStorageError(ctx context.Context, backend, operation string) {
	if r == nil {
		return
	}
	backend = boundedValue(backend, "other", "local", "s3")
	operation = boundedValue(operation, "other", "put", "get", "delete")
	r.avatarStorageErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("avatar.storage_backend", backend),
		attribute.String("avatar.storage_operation", operation),
	))
}

func (r *Runtime) RecordAvatarCleanupPending(ctx context.Context, pending int64) {
	if r == nil {
		return
	}
	if pending < 0 {
		pending = 0
	}
	r.avatarCleanupPending.Record(ctx, pending)
}

func boundedValue(value, fallback string, allowed ...string) string {
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	return fallback
}

func boundedHTTPMethod(value string) string {
	return boundedValue(value, "OTHER", http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions)
}
