package server

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/auth"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/identity"
	"github.com/nyasharp/nyauth/internal/provider"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/stats"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/redis/go-redis/v9"
)

// Server is the main HTTP server.
type Server struct {
	cfg    *config.Config
	db     *pgxpool.Pool
	rdb    *redis.Client
	webFS  embed.FS
	router *chi.Mux

	// Services
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
	auditStore        *audit.Store
	statsHandler      *stats.Handler
}

// New creates a new server instance.
func New(cfg *config.Config, db *pgxpool.Pool, rdb *redis.Client, webFS embed.FS) *Server {
	// Stores
	userStore := user.NewStore(db)
	clientStore := client.NewStore(db)
	identityStore := identity.NewStore(db)
	sessionStore := session.NewStore(rdb)

	// Services
	userService := user.NewService(userStore)
	clientService := client.NewService(clientStore)

	// JWK Manager
	jwkManager := auth.NewJWKManager(db, cfg.Auth.JWK.KeySize, cfg.Auth.JWK.RotationInterval)

	// Token Service
	tokenService := auth.NewTokenService(jwkManager, sessionStore, cfg.Auth.Issuer,
		cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL)

	// Provider Manager
	encKey := []byte(cfg.Auth.EncryptionKey)
	if len(encKey) < 32 {
		// Pad or truncate to exactly 32 bytes
		padded := make([]byte, 32)
		copy(padded, encKey)
		encKey = padded
	}
	providerMgr := provider.NewManager(db, encKey)
	providerMgr.LoadStatic(cfg.Providers)

	// Auth Handler
	authHandler := auth.NewHandler(tokenService, jwkManager, userService, clientStore, sessionStore, cfg)

	// Consent Handler
	consentHandler := auth.NewConsentHandler(sessionStore, tokenService, clientStore, cfg)

	// Session Middleware
	sessionMW := NewSessionMiddleware(sessionStore)

	// Audit Store
	auditStore := audit.NewStore(db)

	// Stats Handler
	statsHandler := stats.NewHandler(db, rdb)

	s := &Server{
		cfg:           cfg,
		db:            db,
		rdb:           rdb,
		webFS:         webFS,
		userService:   userService,
		clientService: clientService,
		providerMgr:  providerMgr,
		identityStore: identityStore,
		sessionStore:  sessionStore,
		tokenService:  tokenService,
		jwkManager:    jwkManager,
		authHandler:   authHandler,
		consentHandler: consentHandler,
		sessionMiddleware: sessionMW,
		auditStore:    auditStore,
		statsHandler:  statsHandler,
	}

	s.router = s.buildRouter()
	return s
}

// buildRouter constructs the chi router with all routes.
func (s *Server) buildRouter() *chi.Mux {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// OAuth 2.0 / OIDC routes (no prefix, well-known paths need to be at root)
	r.Route("/", func(r chi.Router) {
		r.Mount("/", s.authHandler.Routes())
	})

	// Auth callback routes for external providers
	r.Route("/auth", func(r chi.Router) {
		r.Get("/{provider}/authorize", s.handleProviderAuthorize)
		r.Get("/{provider}/callback", s.handleProviderCallback)
	})

	// Login / Logout API
	r.Route("/api", func(r chi.Router) {
		r.Post("/login", s.handleLogin)
		r.Post("/logout", s.handleLogout)
		r.Get("/me", s.handleMe)
		r.Put("/me", s.handleUpdateMe)

		// Provider list (public, for login page)
		r.Get("/providers", s.handleListProviders)

		// Consent API
		r.Get("/consent", s.consentHandler.GetConsent)
		r.Post("/consent/accept", s.consentHandler.AcceptConsent)
		r.Post("/consent/deny", s.consentHandler.DenyConsent)

		// Admin routes (require authentication)
		r.Group(func(r chi.Router) {
			r.Use(s.adminAuthMiddleware)
			// Stats
			r.Get("/admin/stats", s.statsHandler.GetStats)
			r.Get("/admin/stats/login-trend", s.statsHandler.GetLoginTrend)
			r.Get("/admin/stats/recent-logins", s.statsHandler.GetRecentLogins)
			// Audit logs
			r.Get("/admin/audit-logs", s.handleListAuditLogs)
			r.Route("/admin/users", func(r chi.Router) {
				r.Mount("/", user.NewHandler(s.userService).Routes())
				r.Get("/{id}/identities", s.handleUserIdentities)
				r.Post("/{id}/suspend", s.handleSuspendUser)
				r.Post("/{id}/activate", s.handleActivateUser)
				r.Put("/{id}/role", s.handleUpdateUserRole)
			})
			r.Route("/admin/clients", func(r chi.Router) {
				r.Mount("/", client.NewHandler(s.clientService).Routes())
			})
			r.Route("/admin/providers", func(r chi.Router) {
				r.Get("/", s.handleAdminListProviders)
				r.Post("/", s.handleAdminCreateProvider)
				r.Put("/{id}", s.handleAdminUpdateProvider)
				r.Delete("/{id}", s.handleAdminDeleteProvider)
				r.Post("/{id}/test", s.handleTestProvider)
			})
		})
	})

	// Serve embedded Web UI for all non-API routes (SPA fallback)
	webFS, err := fs.Sub(s.webFS, "web/build")
	if err == nil {
		fileServer := http.FileServer(http.FS(webFS))
		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			// Skip API and auth routes
			if strings.HasPrefix(r.URL.Path, "/api/") ||
				strings.HasPrefix(r.URL.Path, "/auth/") ||
				strings.HasPrefix(r.URL.Path, "/.well-known/") ||
				r.URL.Path == "/authorize" ||
				r.URL.Path == "/token" ||
				r.URL.Path == "/userinfo" ||
				r.URL.Path == "/revoke" ||
				r.URL.Path == "/introspect" ||
				r.URL.Path == "/end_session" ||
				r.URL.Path == "/health" {
				http.NotFound(w, r)
				return
			}
			// Try to serve the actual file
			path := strings.TrimPrefix(r.URL.Path, "/")
			if path == "" {
				path = "index.html"
			}
			if f, err := webFS.Open(path); err == nil {
				f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
			// SPA fallback: serve index.html
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
		})
	}

	return r
}

// Run starts the server and waits for shutdown signal.
func (s *Server) Run(ctx context.Context) error {
	// Ensure JWK keys exist
	if err := s.jwkManager.EnsureActiveKey(ctx); err != nil {
		return fmt.Errorf("ensuring JWK keys: %w", err)
	}

	// Load dynamic providers
	if err := s.providerMgr.LoadDynamic(ctx); err != nil {
		fmt.Printf("warning: failed to load dynamic providers: %v\n", err)
	}

	// Create initial admin if configured
	if s.cfg.Admin.Username != "" {
		if err := s.userService.CreateInitialAdmin(ctx, s.cfg.Admin.Username, s.cfg.Admin.Password, s.cfg.Admin.Email); err != nil {
			fmt.Printf("warning: failed to create initial admin: %v\n", err)
		}
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	errCh := make(chan error, 1)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		fmt.Println("\nshutting down gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	fmt.Printf("nyauth server starting on %s\n", addr)
	fmt.Printf("  issuer: %s\n", s.cfg.Auth.Issuer)
	fmt.Printf("  OIDC discovery: %s/.well-known/openid-configuration\n", s.cfg.Auth.Issuer)

	if s.cfg.Server.TLS.Enabled {
		if err := srv.ListenAndServeTLS(s.cfg.Server.TLS.CertFile, s.cfg.Server.TLS.KeyFile); err != http.ErrServerClosed {
			return err
		}
	} else {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			return err
		}
	}

	return <-errCh
}
