package api

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"kosiro/agent/internal/db"
	"kosiro/agent/internal/metrics"
)

func NewRouter(store *db.Store, jwtSecret, dataDir string, collector *metrics.Collector) http.Handler {
	adminToken := os.Getenv("KOSIRO_ADMIN_TOKEN")
	composeDir := os.Getenv("KOSIRO_COMPOSE_DIR")
	h := &Handler{
		store:      store,
		jwtSecret:  jwtSecret,
		adminToken: adminToken,
		dataDir:    dataDir,
		composeDir: composeDir,
		collector:  collector,
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	r.Get("/health", h.Health)
	r.Get("/sub/{token}", h.PublicSubscription)

	if panelRoot := panelStaticDir(); panelRoot != "" {
		fs := http.StripPrefix("/panel/", http.FileServer(http.Dir(panelRoot)))
		r.Get("/panel", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/panel/", http.StatusFound)
		})
		r.Handle("/panel/*", fs)
	}

	r.Route("/v1", func(r chi.Router) {
		r.Post("/auth/token", h.IssueToken)
		r.Group(func(r chi.Router) {
			r.Use(BearerAuth(jwtSecret, adminToken))
			r.Post("/auth/rotate", h.RotateToken)
			r.Get("/system/metrics", h.SystemMetrics)
			r.Get("/system/metrics/history", h.MetricsHistory)
			r.Get("/alerts/stale-protocols", h.StaleProtocols)

			r.Get("/protocols", h.ListProtocols)
			r.Get("/protocols/{id}", h.GetProtocol)
			r.Put("/protocols/{id}", h.PutProtocol)
			r.Post("/protocols/{id}/install", h.InstallProtocol)
			r.Post("/protocols/apply", h.ApplyProtocols)

			r.Get("/users", h.ListUsers)
			r.Post("/users", h.CreateUser)
			r.Get("/users/{id}", h.GetUser)
			r.Patch("/users/{id}", h.PatchUser)
			r.Delete("/users/{id}", h.DeleteUser)
			r.Get("/users/{id}/subscription", h.UserSubscription)
			r.Get("/users/{id}/traffic", h.UserTrafficHistory)

			r.Get("/settings/subscription", h.GetSubscriptionSettings)
			r.Put("/settings/subscription", h.PutSubscriptionSettings)
			r.Get("/settings/xray", h.GetXraySettings)
			r.Put("/settings/xray", h.PutXraySettings)
			r.Get("/settings/singbox", h.GetSingboxSettings)
			r.Put("/settings/singbox", h.PutSingboxSettings)
		})
	})

	return r
}

func panelStaticDir() string {
	if v := os.Getenv("KOSIRO_PANEL_STATIC"); v != "" {
		return v
	}
	candidates := []string{
		"/compose/static/panel",
		"../../deploy/static/panel",
	}
	for _, c := range candidates {
		if st, err := os.Stat(filepath.Join(c, "index.html")); err == nil && !st.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}
