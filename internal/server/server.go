package server

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/auth"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/identity"
	"github.com/nyasharp/nyauth/internal/provider"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/stats"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	cfg               *config.Config
	db                *pgxpool.Pool
	rdb               *redis.Client
	webFS             embed.FS
	router            *chi.Mux
	trustedProxies    []*net.IPNet
	userService       *user.Service
	clientService     *client.Service
	providerMgr       *provider.Manager
	identityStore     *identity.Store
	sessionStore      *session.Store
	tokenService      *auth.TokenService
	jwkManager        *auth.JWKManager
	authHandler       *auth.Handler
	consentHandler    *auth.ConsentHandler
	sessionMiddleware *SessionMiddleware
	loginLimiter      *LoginLimiter
	auditStore        *audit.Store
	statsHandler      *stats.Handler
}

func New(cfg *config.Config, db *pgxpool.Pool, rdb *redis.Client, webFS embed.FS) *Server {
	crypto.SetArgon2Concurrency(cfg.Auth.Argon2Concurrency)
	userStore := user.NewStore(db)
	clientStore := client.NewStore(db)
	identityStore := identity.NewStore(db)
	sessionStore := session.NewStore(rdb)
	userService := user.NewService(userStore)
	clientService := client.NewService(clientStore)
	jwkManager := auth.NewJWKManager(db, cfg.Auth.JWK.KeySize, cfg.Auth.JWK.RotationInterval)
	tokenService := auth.NewTokenService(jwkManager, sessionStore, cfg.Auth.Issuer, cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL)
	providerMgr := provider.NewManager(db, cfg.Auth.MasterKey, cfg.IsProduction())
	providerMgr.LoadStatic(cfg.Providers)
	authHandler := auth.NewHandler(tokenService, jwkManager, userService, clientStore, sessionStore, cfg)
	consentHandler := auth.NewConsentHandler(sessionStore, tokenService, clientStore, cfg)
	s := &Server{cfg: cfg, db: db, rdb: rdb, webFS: webFS, trustedProxies: parseTrustedProxyCIDRs(cfg.Server.TrustedProxyCIDRs), userService: userService, clientService: clientService, providerMgr: providerMgr, identityStore: identityStore, sessionStore: sessionStore, tokenService: tokenService, jwkManager: jwkManager, authHandler: authHandler, consentHandler: consentHandler, sessionMiddleware: NewSessionMiddleware(sessionStore, cfg.Server.SecureCookie), loginLimiter: NewLoginLimiter(rdb), auditStore: audit.NewStore(db), statsHandler: stats.NewHandler(db, rdb)}
	s.router = s.buildRouter()
	return s
}

func (s *Server) buildRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(s.clientIPMiddleware)
	r.Use(redactedRequestLogger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	issuer, _ := url.Parse(s.cfg.Auth.Issuer)
	allowedOrigin := issuer.Scheme + "://" + issuer.Host
	r.Use(cors.Handler(cors.Options{AllowedOrigins: []string{allowedOrigin}, AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}, AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"}, ExposedHeaders: []string{"Retry-After"}, AllowCredentials: true, MaxAge: 300}))
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Mount("/", s.authHandler.Routes())
	r.Route("/auth", func(r chi.Router) {
		r.Get("/{provider}/authorize", s.handleProviderAuthorize)
		r.Get("/{provider}/callback", s.handleProviderCallback)
	})
	r.Route("/api", func(r chi.Router) {
		r.Post("/login", s.handleLogin)
		r.Get("/providers", s.handleListProviders)
		r.Group(func(r chi.Router) {
			r.Use(s.userAuthMiddleware)
			r.Use(s.mutationAuditMiddleware)
			r.Use(s.requireCurrentPasswordChange)
			r.Use(s.csrfMiddleware)
			r.Get("/session", s.handleSession)
			r.Post("/logout", s.handleLogout)
			r.Get("/me", s.handleMe)
			r.Put("/me", s.handleUpdateMe)
			r.Post("/me/password", s.handleChangePassword)
			r.Get("/me/identities", s.handleMyIdentities)
			r.Post("/me/identities/{provider}/bind", s.handleProviderBind)
			r.Get("/consent", s.consentHandler.GetConsent)
			r.Post("/consent/accept", s.consentHandler.AcceptConsent)
			r.Post("/consent/deny", s.consentHandler.DenyConsent)
			r.Get("/my/clients", s.handleListMyClients)
			r.Post("/my/clients", s.handleCreateMyClient)
			r.Delete("/my/clients/{id}", s.handleDeleteMyClient)
		})
		r.Group(func(r chi.Router) {
			r.Use(s.adminAuthMiddleware)
			r.Use(s.mutationAuditMiddleware)
			r.Use(s.requireCurrentPasswordChange)
			r.Use(s.csrfMiddleware)
			r.Get("/admin/stats", s.statsHandler.GetStats)
			r.Get("/admin/stats/login-trend", s.statsHandler.GetLoginTrend)
			r.Get("/admin/stats/recent-logins", s.statsHandler.GetRecentLogins)
			r.Get("/admin/audit-logs", s.handleListAuditLogs)
			userHandler := user.NewHandler(s.userService)
			r.Get("/admin/users", userHandler.List)
			r.Post("/admin/users", userHandler.Create)
			r.Get("/admin/users/{id}", userHandler.Get)
			r.Put("/admin/users/{id}", userHandler.Update)
			r.Delete("/admin/users/{id}", userHandler.Delete)
			r.Post("/admin/users/{id}/reset-password", userHandler.ResetPassword)
			r.Get("/admin/users/{id}/identities", s.handleUserIdentities)
			r.Post("/admin/users/{id}/suspend", s.handleSuspendUser)
			r.Post("/admin/users/{id}/activate", s.handleActivateUser)
			r.Put("/admin/users/{id}/role", s.handleUpdateUserRole)
			clientHandler := client.NewHandler(s.clientService)
			r.Get("/admin/clients", clientHandler.List)
			r.Post("/admin/clients", clientHandler.Create)
			r.Get("/admin/clients/{id}", clientHandler.Get)
			r.Put("/admin/clients/{id}", clientHandler.Update)
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
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/auth/") || strings.HasPrefix(r.URL.Path, "/.well-known/") || r.URL.Path == "/authorize" || r.URL.Path == "/token" || r.URL.Path == "/userinfo" || r.URL.Path == "/revoke" || r.URL.Path == "/introspect" || r.URL.Path == "/end_session" || r.URL.Path == "/health" {
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
	if err := s.jwkManager.EnsureActiveKey(ctx); err != nil {
		return fmt.Errorf("ensuring JWK keys: %w", err)
	}
	if err := s.providerMgr.LoadDynamic(ctx); err != nil {
		return fmt.Errorf("loading providers: %w", err)
	}
	bootstrap, err := s.userService.BootstrapInitialAdmin(ctx, s.cfg.Admin.Username, s.cfg.Admin.Password, s.cfg.Admin.Email)
	if err != nil {
		return fmt.Errorf("bootstrapping administrator: %w", err)
	}
	if bootstrap.Created {
		if bootstrap.GeneratedPassword != "" {
			fmt.Printf("BOOTSTRAP ADMIN PASSWORD (shown once): %s\n", bootstrap.GeneratedPassword)
		} else {
			fmt.Println("bootstrap administrator created; configured password was not logged")
		}
	}
	server := &http.Server{Addr: fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port), Handler: s.router, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	runCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go s.rotateJWKs(runCtx)
	go func() {
		<-runCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	fmt.Printf("nyauth server starting on %s (issuer %s)\n", server.Addr, s.cfg.Auth.Issuer)
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
			if err := s.jwkManager.RotateKeys(ctx); err != nil {
				fmt.Printf("warning: JWK rotation failed: %v\n", err)
			}
		}
	}
}
