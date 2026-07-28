package server

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/auth"
	"github.com/nyasharp/nyauth/internal/authorization"
	"github.com/nyasharp/nyauth/internal/avatar"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/identity"
	"github.com/nyasharp/nyauth/internal/invite"
	"github.com/nyasharp/nyauth/internal/mailruntime"
	"github.com/nyasharp/nyauth/internal/mfa"
	"github.com/nyasharp/nyauth/internal/provider"
	"github.com/nyasharp/nyauth/internal/registration"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/internal/stats"
	"github.com/nyasharp/nyauth/internal/telemetry"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	cfg                 *config.Config
	db                  *pgxpool.Pool
	rdb                 *redis.Client
	webFS               embed.FS
	router              *chi.Mux
	trustedProxies      []*net.IPNet
	userService         *user.Service
	clientService       *client.Service
	providerMgr         *provider.Manager
	identityStore       *identity.Store
	sessionStore        *session.Store
	tokenService        *auth.TokenService
	jwkManager          *auth.JWKManager
	authHandler         *auth.Handler
	consentHandler      *auth.ConsentHandler
	sessionMiddleware   *SessionMiddleware
	loginLimiter        *LoginLimiter
	auditStore          *audit.Store
	auditDispatcher     *audit.Dispatcher
	authorizationStore  *authorization.Store
	statsHandler        *stats.Handler
	settingsMgr         *settings.Manager
	inviteStore         *invite.Store
	registrationStore   *registration.Store
	telemetry           *telemetry.Runtime
	accountService      accountActionService
	accountLimiter      *AccountActionLimiter
	mailSettingsLimiter *MailSettingsLimiter
	avatarLimiter       *AvatarLimiter
	mailManager         *mailruntime.Manager
	mfaService          *mfa.Service
	avatarService       *avatar.Service
	avatarRepository    *avatar.Repository
	avatarStore         avatar.BlobStore
	avatarImportWorker  *avatar.ImportWorker
	avatarProcessing    chan struct{}
	emailDispatcher     *account.Dispatcher
	readiness           readinessState
}

func New(cfg *config.Config, db *pgxpool.Pool, rdb *redis.Client, webFS embed.FS, telemetryRuntime *telemetry.Runtime) (*Server, error) {
	crypto.SetArgon2Concurrency(cfg.Auth.Argon2Concurrency)
	issuerURL, err := url.Parse(cfg.Auth.Issuer)
	if err != nil {
		return nil, fmt.Errorf("parsing Passkey issuer: %w", err)
	}
	passkeyRPID := strings.ToLower(issuerURL.Hostname())
	rpOrigin := (&url.URL{Scheme: issuerURL.Scheme, Host: issuerURL.Host}).String()
	userStore := user.NewStoreForRP(db, passkeyRPID)
	clientStore := client.NewStore(db)
	authorizationStore := authorization.NewStore(db)
	identityStore := identity.NewStoreForRP(db, passkeyRPID)
	sessionStore := session.NewStore(rdb)
	userService := user.NewService(userStore)
	clientService := client.NewService(clientStore)
	jwkManager := auth.NewJWKManager(db, cfg.Auth.JWK.KeySize, cfg.Auth.JWK.RotationInterval)
	tokenService := auth.NewTokenService(jwkManager, sessionStore, cfg.Auth.Issuer, cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL)
	providerMgr := provider.NewManager(db, cfg.Auth.MasterKey, cfg.IsProduction())
	avatarRepository := avatar.NewRepository(db)
	var avatarStore avatar.BlobStore
	mediaInitCtx, cancelMediaInit := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelMediaInit()
	switch cfg.Media.Backend {
	case "local":
		avatarStore, err = avatar.NewLocalStore(cfg.Media.Local.Directory)
	case "s3":
		avatarStore, err = avatar.NewS3Store(mediaInitCtx, cfg.Media.S3)
	default:
		err = fmt.Errorf("unsupported media backend %q", cfg.Media.Backend)
	}
	if err != nil {
		return nil, fmt.Errorf("configuring avatar media storage: %w", err)
	}
	if err := avatarRepository.EnsureStorageBackendCompatible(mediaInitCtx, avatarStore.Backend()); err != nil {
		return nil, fmt.Errorf("validating avatar media storage: %w", err)
	}
	avatarService, err := avatar.NewService(avatarRepository, avatarStore, avatar.NewProcessor())
	if err != nil {
		return nil, fmt.Errorf("configuring avatar media service: %w", err)
	}
	authHandler := auth.NewHandler(tokenService, jwkManager, userService, clientStore, sessionStore, cfg)
	consentHandler := auth.NewConsentHandler(sessionStore, tokenService, clientStore, authorizationStore, cfg)
	mfaService, err := mfa.NewService(db, mfa.Options{
		ActiveKeyID: "primary", MasterKeys: map[string][]byte{"primary": cfg.Auth.MasterKey},
		Passkeys: &mfa.PasskeyConfig{
			RPID: passkeyRPID, RPDisplayName: cfg.Web.Title,
			RPOrigins: []string{rpOrigin},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configuring MFA service: %w", err)
	}
	s := &Server{cfg: cfg, db: db, rdb: rdb, webFS: webFS, trustedProxies: parseTrustedProxyCIDRs(cfg.Server.TrustedProxyCIDRs), userService: userService, clientService: clientService, providerMgr: providerMgr, identityStore: identityStore, sessionStore: sessionStore, tokenService: tokenService, jwkManager: jwkManager, authHandler: authHandler, consentHandler: consentHandler, sessionMiddleware: NewSessionMiddleware(sessionStore, cfg.Server.SecureCookie), loginLimiter: NewLoginLimiter(rdb), accountLimiter: NewAccountActionLimiter(rdb), mailSettingsLimiter: NewMailSettingsLimiter(rdb), avatarLimiter: NewAvatarLimiter(rdb), auditStore: audit.NewStore(db), authorizationStore: authorizationStore, statsHandler: stats.NewHandler(db, rdb), settingsMgr: settings.NewManagerForRP(db, settings.Branding{Title: cfg.Web.Title, LogoURL: cfg.Web.LogoURL}, passkeyRPID), inviteStore: invite.NewStore(db), registrationStore: registration.NewStore(db), telemetry: telemetryRuntime, mfaService: mfaService, avatarService: avatarService, avatarRepository: avatarRepository, avatarStore: avatarStore, avatarProcessing: make(chan struct{}, 1)}
	if err := telemetryRuntime.BindPoolObservers(db, rdb); err != nil {
		return nil, fmt.Errorf("configuring dependency pool metrics: %w", err)
	}
	authHandler.SetGrantMetricSink(telemetryRuntime.RecordOAuthGrant)
	providerMgr.SetTelemetrySink(telemetryRuntime.RecordProviderEvent)
	authHandler.SetSecurityAuditSink(func(ctx context.Context, event auth.SecurityAuditEvent) error {
		ipAddress, _ := ctx.Value(clientIPContextKey).(string)
		err := audit.EnqueueTargetResult(
			ctx, s.auditStore, event.Event, event.ActorID, event.ActorName,
			event.AggregateType, event.AggregateID, event.Result, event.RiskLevel,
			ipAddress, "", event.Details,
		)
		if err != nil {
			telemetryRuntime.RecordAuditFailure(ctx, event.Event)
		}
		return err
	})
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "nyauth"
	}
	workerPrefix := fmt.Sprintf("%s-%d", hostname, os.Getpid())
	avatarImportWorker, err := avatar.NewImportWorker(avatarRepository, avatarService, avatar.ImportWorkerOptions{
		WorkerID:   workerPrefix + "-avatar-import",
		MasterKeys: map[string][]byte{"primary": cfg.Auth.MasterKey},
		Policy: func(providerID uuid.UUID) (avatar.ImportPolicy, bool) {
			policy, ok := providerMgr.AvatarPolicyByID(providerID)
			return avatar.ImportPolicy{Enabled: policy.Enabled, AllowedHosts: policy.AllowedHosts}, ok
		},
		OnResult: func(ctx context.Context, job models.ProviderAvatarImportJob, result, reason string, duration time.Duration) {
			telemetryRuntime.RecordAvatarOperation(ctx, "provider_import", result, reason, duration)
			if result != "success" && result != "failure" {
				return
			}
			event := models.AuditProviderAvatarImported
			risk := "low"
			if result == "failure" {
				event = models.AuditProviderAvatarFailed
				risk = "medium"
			}
			s.enqueueAuditTargetResult(ctx, event, nil, "", "user", job.UserID.String(), result, risk, "", "", map[string]any{
				"provider_id": job.ProviderID.String(), "reason": reason,
			})
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configuring provider avatar import worker: %w", err)
	}
	s.avatarImportWorker = avatarImportWorker
	auditDispatcher, err := audit.NewDispatcher(s.auditStore, audit.DispatcherOptions{
		WorkerID: workerPrefix + "-audit",
		OnError: func(ctx context.Context, event string, err error) {
			slog.ErrorContext(ctx, "audit outbox dispatch failed", "event", event, "error", err)
			telemetryRuntime.RecordAuditFailure(ctx, event)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configuring audit dispatcher: %w", err)
	}
	s.auditDispatcher = auditDispatcher
	accountStore := account.NewStore(db)
	publicBaseURL := cfg.Mail.PublicBaseURL
	if strings.TrimSpace(publicBaseURL) == "" {
		publicBaseURL = cfg.Auth.Issuer
	}
	accountService, err := account.NewService(accountStore, account.ServiceOptions{
		PublicBaseURL: publicBaseURL, ActiveKeyID: "primary",
		MasterKeys:      map[string][]byte{"primary": cfg.Auth.MasterKey},
		OnEmailVerified: telemetryRuntime.RecordEmailVerificationDuration,
	})
	if err != nil {
		return nil, fmt.Errorf("configuring account recovery: %w", err)
	}
	mailStore, err := mailruntime.NewStore(db, mailruntime.StoreOptions{
		ActiveKeyID: "primary", MasterKeys: map[string][]byte{"primary": cfg.Auth.MasterKey},
	})
	if err != nil {
		return nil, fmt.Errorf("configuring runtime mail storage: %w", err)
	}
	var fallback *mailruntime.SMTPConfig
	if cfg.Mail.Enabled {
		fallback = &mailruntime.SMTPConfig{
			Settings: mailruntime.Settings{
				Host: cfg.Mail.SMTP.Host, Port: cfg.Mail.SMTP.Port, Username: cfg.Mail.SMTP.Username,
				TLSMode: cfg.Mail.SMTP.TLSMode, FromAddress: cfg.Mail.FromAddress, FromName: cfg.Mail.FromName,
				PublicBaseURL: cfg.Mail.PublicBaseURL, ConnectTimeout: cfg.Mail.SMTP.ConnectTimeout,
				SendTimeout: cfg.Mail.SMTP.SendTimeout,
			},
			Password: cfg.Mail.SMTP.Password,
		}
	}
	mailManager, err := mailruntime.NewManager(mailStore, mailruntime.ManagerOptions{
		Fallback: fallback, Production: cfg.IsProduction(),
		OnError: func(err error) { slog.Error("runtime mail operation failed", "error", err) },
		OnSnapshot: func(effective mailruntime.EffectiveConfig) {
			telemetryRuntime.RecordSMTPCircuitState(context.Background(), effective.CircuitState)
			if effective.Config != nil {
				if err := accountService.SetPublicBaseURL(effective.Config.PublicBaseURL); err != nil {
					slog.Error("runtime mail public URL update failed", "error", err)
				}
			}
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configuring runtime mail manager: %w", err)
	}
	if err := mailManager.Load(context.Background()); err != nil {
		slog.Error("initial runtime mail load failed", "error", err)
	}
	notificationBuilder := runtimeSecurityNotificationBuilder{manager: mailManager, service: accountService}
	userStore.SetSecurityNotificationBuilder(notificationBuilder)
	identityStore.SetSecurityNotificationBuilder(notificationBuilder)
	dispatcher, err := account.NewDynamicDispatcher(accountStore, mailManager, account.DispatcherOptions{
		WorkerID:   workerPrefix + "-email",
		MasterKeys: map[string][]byte{"primary": cfg.Auth.MasterKey},
		OnError:    func(err error) { slog.Error("email outbox dispatch failed", "error", err) },
		OnDelivery: telemetryRuntime.RecordSMTPDelivery,
		OnSMTPError: func(ctx context.Context, category account.SMTPErrorCategory) {
			telemetryRuntime.RecordSMTPError(ctx, string(category))
		},
		OnBacklog: telemetryRuntime.RecordSMTPBacklog,
	})
	if err != nil {
		return nil, fmt.Errorf("configuring email dispatcher: %w", err)
	}
	s.accountService = accountService
	s.mailManager = mailManager
	s.emailDispatcher = dispatcher
	s.readiness.checks = s.runtimeReadinessChecks()
	s.router = s.buildRouter()
	return s, nil
}

func (s *Server) buildRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(s.clientIPMiddleware)
	if s.telemetry != nil {
		r.Use(s.telemetry.HTTPMiddleware)
	}
	r.Use(redactedRequestLogger)
	r.Use(structuredRecoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	issuer, _ := url.Parse(s.cfg.Auth.Issuer)
	allowedOrigin := issuer.Scheme + "://" + issuer.Host
	r.Use(cors.Handler(cors.Options{AllowedOrigins: []string{allowedOrigin}, AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}, AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-WebAuthn-Ceremony"}, ExposedHeaders: []string{"Retry-After"}, AllowCredentials: true, MaxAge: 300}))
	r.Get("/livez", s.handleLiveness)
	r.Get("/readyz", s.handleReadiness)
	r.Get("/media/avatars/{avatar_id}/{size}.webp", s.handleAvatarMedia)
	if s.telemetry != nil {
		r.With(s.requireInternalMetricsClient).Handle("/metrics", s.telemetry.PrometheusHandler())
	}
	r.Mount("/", s.authHandler.Routes())
	r.Route("/auth", func(r chi.Router) {
		r.Get("/{provider}/authorize", s.handleProviderAuthorize)
		r.Get("/{provider}/callback", s.handleProviderCallback)
	})
	r.Route("/api", func(r chi.Router) {
		r.Post("/login", s.handleLogin)
		r.Post("/login/passkey/options", s.handleBeginPasskeyLogin)
		r.Post("/login/passkey/verify", s.handleFinishPasskeyLogin)
		r.Get("/login/mfa", s.handleGetMFAChallenge)
		r.Post("/login/mfa", s.handleVerifyMFAChallenge)
		r.Post("/login/mfa/passkey/options", s.handleBeginMFAPasskey)
		r.Post("/login/mfa/passkey/verify", s.handleFinishMFAPasskey)
		r.Delete("/login/mfa", s.handleCancelMFAChallenge)
		r.Get("/branding", s.handleGetBranding)
		r.Get("/registration", s.handleRegistrationOptions)
		r.Post("/register", s.handleRegister)
		r.Get("/providers", s.handleListProviders)
		r.Post("/password/forgot", s.handleRequestPasswordReset)
		r.Post("/password/reset", s.handleConfirmPasswordReset)
		r.Post("/email/verify", s.handleConfirmEmailVerification)
		r.Post("/email/verification/resend", s.handleResendPendingEmailVerification)
		r.Post("/email/change/confirm", s.handleConfirmEmailChange)
		r.Group(func(r chi.Router) {
			r.Use(s.userAuthMiddleware)
			r.Use(s.mutationAuditMiddleware)
			r.Use(s.requireCurrentPasswordChange)
			r.Use(s.csrfMiddleware)
			r.Get("/session", s.handleSession)
			r.Post("/logout", s.handleLogout)
			r.Get("/me", s.handleMe)
			r.Put("/me", s.handleUpdateMe)
			r.Post("/me/avatar", s.handleUploadMyAvatar)
			r.Delete("/me/avatar", s.handleDeleteMyAvatar)
			r.Post("/me/password", s.handleChangePassword)
			r.Post("/me/password/set", s.handleSetPassword)
			r.Post("/me/reauth/password", s.handlePasswordReauthentication)
			r.Post("/me/reauth/{provider}", s.handleProviderReauthentication)
			r.Post("/me/reauth/passkey/options", s.handleBeginPasskeyReauthentication)
			r.Post("/me/reauth/passkey/verify", s.handleFinishPasskeyReauthentication)
			r.Get("/me/mfa", s.handleGetMyMFA)
			r.Post("/me/mfa/totp/enroll", s.handleBeginTOTPEnrollment)
			r.Post("/me/mfa/totp/enroll/confirm", s.handleConfirmTOTPEnrollment)
			r.Post("/me/mfa/recovery-codes", s.handleRegenerateRecoveryCodes)
			r.Delete("/me/mfa/totp", s.handleDisableTOTP)
			r.Get("/me/passkeys", s.handleListPasskeys)
			r.Post("/me/passkeys/registration/options", s.handleBeginPasskeyRegistration)
			r.Post("/me/passkeys/registration/verify", s.handleFinishPasskeyRegistration)
			r.Put("/me/passkeys/{id}", s.handleRenamePasskey)
			r.Delete("/me/passkeys/{id}", s.handleDeletePasskey)
			r.Post("/me/email/verification", s.handleRequestEmailVerification)
			r.Post("/me/email/change", s.handleRequestEmailChange)
			r.Get("/me/sessions", s.handleListMySessions)
			r.Delete("/me/sessions/{id}", s.handleDeleteMySession)
			r.Post("/me/sessions/revoke-others", s.handleRevokeOtherSessions)
			r.Get("/me/authorizations", s.handleListMyAuthorizations)
			r.Delete("/me/authorizations/{client_id}", s.handleRevokeMyAuthorization)
			r.Get("/me/identities", s.handleMyIdentities)
			r.Post("/me/identities/{provider}/bind", s.handleProviderBind)
			r.Delete("/me/identities/{id}", s.handleDeleteMyIdentity)
			r.Get("/consent", s.consentHandler.GetConsent)
			r.Post("/consent/accept", s.consentHandler.AcceptConsent)
			r.Post("/consent/deny", s.consentHandler.DenyConsent)
			r.Get("/my/clients", s.handleListMyClients)
			r.Post("/my/clients", s.handleCreateMyClient)
			r.Post("/my/clients/{id}/rotate-secret", s.handleRotateMyClientSecret)
			r.Delete("/my/clients/{id}", s.handleDeleteMyClient)
		})
		r.Group(func(r chi.Router) {
			r.Use(s.adminAuthMiddleware)
			r.Use(s.mutationAuditMiddleware)
			r.Use(s.requireCurrentPasswordChange)
			r.Use(s.csrfMiddleware)
			r.Get("/admin/system/status", s.handleSystemStatus)
			r.Put("/admin/branding", s.handleUpdateBranding)
			r.Get("/admin/settings/registration", s.handleGetRegistrationSettings)
			r.Put("/admin/settings/registration", s.handleUpdateRegistrationSettings)
			r.Get("/admin/settings/security", s.handleGetSecuritySettings)
			r.Put("/admin/settings/security", s.handleUpdateSecuritySettings)
			r.Get("/admin/settings/mail", s.handleGetMailSettings)
			r.Put("/admin/settings/mail/candidate", s.handleSaveMailCandidate)
			r.Post("/admin/settings/mail/candidate/test", s.handleTestMailCandidate)
			r.Post("/admin/settings/mail/activate", s.handleActivateMailCandidate)
			r.Post("/admin/settings/mail/rollback", s.handleRollbackMailSettings)
			r.Post("/admin/settings/mail/disable", s.handleDisableMail)
			r.Get("/admin/invites", s.handleListInvites)
			r.Post("/admin/invites", s.handleCreateInvite)
			r.Delete("/admin/invites/{id}", s.handleRevokeInvite)
			r.Get("/admin/stats", s.statsHandler.GetStats)
			r.Get("/admin/stats/login-trend", s.statsHandler.GetLoginTrend)
			r.Get("/admin/stats/registration-trend", s.statsHandler.GetRegistrationTrend)
			r.Get("/admin/stats/mail-trend", s.statsHandler.GetMailTrend)
			r.Get("/admin/stats/recent-logins", s.statsHandler.GetRecentLogins)
			r.Get("/admin/audit-logs/options", s.handleAuditLogOptions)
			r.Get("/admin/audit-logs", s.handleListAuditLogs)
			r.Get("/admin/audit-logs/export", s.handleExportAuditLogs)
			userHandler := user.NewHandler(s.userService)
			r.Get("/admin/users", userHandler.List)
			r.Post("/admin/users", userHandler.Create)
			r.Get("/admin/users/{id}", userHandler.Get)
			r.Get("/admin/users/{id}/overview", s.handleAdminUserOverview)
			r.Get("/admin/users/{id}/security", s.handleAdminUserSecurity)
			r.Get("/admin/users/{id}/authorizations", s.handleAdminUserAuthorizations)
			r.Get("/admin/users/{id}/clients", s.handleAdminUserClients)
			r.Get("/admin/users/{id}/activity", s.handleAdminUserActivity)
			r.Put("/admin/users/{id}", s.handleAdminUpdateUser)
			r.Delete("/admin/users/{id}", userHandler.Delete)
			r.Post("/admin/users/{id}/avatar", s.handleUploadUserAvatar)
			r.Delete("/admin/users/{id}/avatar", s.handleDeleteUserAvatar)
			r.Post("/admin/users/{id}/reset-password", s.handleAdminResetPassword)
			r.Get("/admin/users/{id}/identities", s.handleUserIdentities)
			r.Delete("/admin/users/{id}/identities/{identity_id}", s.handleAdminDeleteUserIdentity)
			r.Get("/admin/users/{id}/sessions", s.handleAdminListUserSessions)
			r.Delete("/admin/users/{id}/sessions/{session_id}", s.handleAdminDeleteUserSession)
			r.Delete("/admin/users/{id}/sessions", s.handleAdminRevokeUserSessions)
			r.Post("/admin/users/{id}/suspend", s.handleSuspendUser)
			r.Post("/admin/users/{id}/activate", s.handleActivateUser)
			r.Put("/admin/users/{id}/role", s.handleUpdateUserRole)
			clientHandler := client.NewHandler(s.clientService)
			r.Get("/admin/clients", clientHandler.List)
			r.Post("/admin/clients", clientHandler.Create)
			r.Get("/admin/clients/{id}", clientHandler.Get)
			r.Put("/admin/clients/{id}", clientHandler.Update)
			r.Put("/admin/clients/{id}/owner", clientHandler.UpdateOwner)
			r.Get("/admin/clients/{id}/access-users", clientHandler.ListAccessUsers)
			r.Put("/admin/clients/{id}/access-users", clientHandler.ReplaceAccessUsers)
			r.Post("/admin/clients/{id}/rotate-secret", clientHandler.RotateSecret)
			r.Delete("/admin/clients/{id}", clientHandler.Delete)
			r.Get("/admin/providers", s.handleAdminListProviders)
			r.Post("/admin/providers", s.handleAdminCreateProvider)
			r.Put("/admin/providers/{id}", s.handleAdminUpdateProvider)
			r.Delete("/admin/providers/{id}", s.handleAdminDeleteProvider)
			r.Post("/admin/providers/{id}/test", s.handleTestProvider)
		})
	})
	s.mountWeb(r)
	return r
}

func (s *Server) mountWeb(r *chi.Mux) {
	webRoot, err := fs.Sub(s.webFS, "web/build")
	if err != nil {
		return
	}
	fileServer := http.FileServer(http.FS(webRoot))
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/auth/") || strings.HasPrefix(r.URL.Path, "/media/") || strings.HasPrefix(r.URL.Path, "/.well-known/") || r.URL.Path == "/authorize" || r.URL.Path == "/token" || r.URL.Path == "/userinfo" || r.URL.Path == "/revoke" || r.URL.Path == "/introspect" || r.URL.Path == "/end_session" || r.URL.Path == "/livez" || r.URL.Path == "/readyz" || r.URL.Path == "/metrics" {
			http.NotFound(w, r)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if file, err := webRoot.Open(path); err == nil {
			_ = file.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}

func (s *Server) Run(ctx context.Context) error {
	s.readiness.accepting.Store(false)
	jwkStarted := time.Now()
	if err := s.jwkManager.EnsureActiveKey(ctx); err != nil {
		s.telemetry.RecordJWKRotation(ctx, "startup", "failure", "initialization_failed", time.Since(jwkStarted))
		return fmt.Errorf("ensuring JWK keys: %w", err)
	}
	s.telemetry.RecordJWKRotation(ctx, "startup", "success", "none", time.Since(jwkStarted))
	if err := s.providerMgr.LoadDynamic(ctx); err != nil {
		return fmt.Errorf("loading providers: %w", err)
	}
	bootstrap, err := s.userService.BootstrapInitialAdmin(ctx, s.cfg.Admin.Username, s.cfg.Admin.Password, s.cfg.Admin.Email)
	if err != nil {
		return fmt.Errorf("bootstrapping administrator: %w", err)
	}
	if bootstrap.Created {
		if bootstrap.GeneratedPassword != "" {
			_, _ = fmt.Fprintf(os.Stderr, "BOOTSTRAP ADMIN PASSWORD (shown once): %s\n", bootstrap.GeneratedPassword)
			slog.Warn("bootstrap administrator created with a generated one-time password")
		} else {
			slog.Info("bootstrap administrator created; configured password was not logged")
		}
	}
	if err := s.statsHandler.Refresh(ctx); err != nil {
		slog.WarnContext(ctx, "initial statistics refresh failed", "error_class", "dependency_unavailable")
	}
	s.readiness.accepting.Store(true)
	server := &http.Server{Addr: fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port), Handler: s.router, ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelError), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	runCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	s.providerMgr.StartSynchronization(runCtx)
	if err := s.settingsMgr.Load(runCtx); err != nil {
		slog.WarnContext(runCtx, "initial runtime settings load failed", "error", err)
	}
	s.settingsMgr.StartSynchronization(runCtx)
	if s.mailManager != nil {
		s.mailManager.StartSynchronization(runCtx)
	}
	if s.auditDispatcher != nil {
		go func() {
			if dispatchErr := s.auditDispatcher.Run(runCtx); dispatchErr != nil && !errors.Is(dispatchErr, context.Canceled) {
				slog.ErrorContext(runCtx, "audit dispatcher stopped", "error", dispatchErr)
			}
		}()
	}
	if s.emailDispatcher != nil {
		go func() {
			if dispatchErr := s.emailDispatcher.Run(runCtx); dispatchErr != nil && !errors.Is(dispatchErr, context.Canceled) {
				slog.ErrorContext(runCtx, "email dispatcher stopped", "error", dispatchErr)
			}
		}()
	}
	if s.avatarImportWorker != nil {
		go func() {
			if importErr := s.avatarImportWorker.Run(runCtx); importErr != nil && !errors.Is(importErr, context.Canceled) {
				slog.ErrorContext(runCtx, "provider avatar import worker stopped", "error", importErr)
			}
		}()
	}
	go s.rotateJWKs(runCtx)
	go s.statsHandler.Run(runCtx, time.Minute)
	go s.runRegistrationCleanup(runCtx)
	go s.runAvatarCleanup(runCtx)
	go func() {
		<-runCtx.Done()
		s.readiness.accepting.Store(false)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.Server.ShutdownTimeout)
		defer cancel()
		if shutdownErr := server.Shutdown(shutdownCtx); shutdownErr != nil {
			slog.Warn("graceful HTTP shutdown did not complete", "error", shutdownErr)
		}
	}()
	slog.Info("nyauth server starting", "address", server.Addr, "issuer", s.cfg.Auth.Issuer)
	if s.cfg.Server.TLS.Enabled {
		err = server.ListenAndServeTLS(s.cfg.Server.TLS.CertFile, s.cfg.Server.TLS.KeyFile)
	} else {
		err = server.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) runAvatarCleanup(ctx context.Context) {
	run := func() {
		started := time.Now()
		cleanupCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		result, err := s.avatarService.Cleanup(cleanupCtx, time.Now().UTC(), 15*time.Minute, 100, 10)
		if err != nil {
			s.telemetry.RecordAvatarOperation(ctx, "cleanup", "failure", "storage_unavailable", time.Since(started))
			s.telemetry.RecordAvatarStorageError(ctx, string(s.avatarStore.Backend()), "delete")
			if !errors.Is(err, context.Canceled) {
				slog.ErrorContext(ctx, "avatar media cleanup failed", "error", err)
			}
			return
		}
		s.telemetry.RecordAvatarOperation(ctx, "cleanup", "success", "none", time.Since(started))
		if pending, countErr := s.avatarRepository.CountCleanupPending(ctx, s.avatarStore.Backend()); countErr == nil {
			s.telemetry.RecordAvatarCleanupPending(ctx, pending)
		}
		if result.LockAcquired && result.Rows > 0 {
			slog.InfoContext(ctx, "avatar media cleaned", "rows", result.Rows, "batches", result.Batches)
		}
	}
	run()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func (s *Server) runRegistrationCleanup(ctx context.Context) {
	run := func() {
		result, err := s.registrationStore.CleanupExpired(ctx, time.Now().UTC(), 200, 10)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				slog.ErrorContext(ctx, "expired registration cleanup failed", "error", err)
			}
			return
		}
		if result.LockAcquired && result.Released > 0 {
			slog.InfoContext(ctx, "expired registrations cleaned",
				"released", result.Released, "deleted_users", result.DeletedUsers, "batches", result.Batches)
		}
	}
	run()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func (s *Server) rotateJWKs(ctx context.Context) {
	interval := s.cfg.Auth.JWK.RotationInterval / 4
	if interval > 6*time.Hour {
		interval = 6 * time.Hour
	}
	if interval < time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			started := time.Now()
			if err := s.jwkManager.RotateKeys(ctx); err != nil {
				s.telemetry.RecordJWKRotation(ctx, "scheduled", "failure", "rotation_failed", time.Since(started))
				slog.ErrorContext(ctx, "JWK rotation failed", "error", err)
			} else {
				s.telemetry.RecordJWKRotation(ctx, "scheduled", "success", "none", time.Since(started))
			}
		}
	}
}
