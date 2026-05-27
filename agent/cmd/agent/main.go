package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"kosiro/agent/internal/adminkey"
	"kosiro/agent/internal/api"
	"kosiro/agent/internal/db"
	"kosiro/agent/internal/metrics"
	"kosiro/agent/internal/statsync"
	"kosiro/agent/internal/xray"
)

func main() {
	dataDir := getenv("KOSIRO_DATA_DIR", "/data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Fatalf("data dir: %v", err)
	}

	sqlPath := filepath.Join(dataDir, "kosiro.db")
	store, err := db.Open(sqlPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer store.Close()

	if err := store.Migrate(); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	adminTok := getenv("KOSIRO_ADMIN_TOKEN", "")
	if adminTok != "" {
		if err := store.EnsureAdminKey(adminTok); err != nil {
			log.Printf("admin key persist: %v", err)
		}
	} else if secret := getenv("KOSIRO_INSTALL_SECRET", ""); secret != "" {
		host := getenv("KOSIRO_PUBLIC_HOST", "127.0.0.1")
		key, err := adminkey.Generate(host, secret)
		if err != nil {
			log.Fatalf("admin key: %v", err)
		}
		adminTok = key
		_ = os.Setenv("KOSIRO_ADMIN_TOKEN", key)
		if err := store.EnsureAdminKey(key); err != nil {
			log.Fatalf("admin key save: %v", err)
		}
		log.Printf("kosiro: generated admin key %s", key)
	}

	if err := bootstrapDefaultXray(store, dataDir); err != nil {
		log.Printf("bootstrap xray config: %v", err)
	}

	jwtSecret := getenv("KOSIRO_JWT_SECRET", "")
	if jwtSecret == "" {
		jwtSecret, err = store.EnsureJWTSecret()
		if err != nil {
			log.Fatalf("jwt secret: %v", err)
		}
		log.Printf("kosiro: generated JWT secret (set KOSIRO_JWT_SECRET to persist across restarts)")
	}

	collector := metrics.NewCollector(store)
	go collector.RunBackground(context.Background(), 60*time.Second)

	xrayAPI := getenv("KOSIRO_XRAY_API", "http://127.0.0.1:10085")
	statsWorker := statsync.New(store, xrayAPI)
	go statsWorker.Run(context.Background())

	addr := getenv("KOSIRO_HTTP_ADDR", ":8443")
	tlsCert := getenv("KOSIRO_TLS_CERT", "")
	tlsKey := getenv("KOSIRO_TLS_KEY", "")

	handler := api.NewRouter(store, jwtSecret, dataDir, collector)

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
	}

	go func() {
		var err error
		if tlsCert != "" && tlsKey != "" {
			log.Printf("kosiro agent listening on %s (TLS)", addr)
			err = srv.ListenAndServeTLS(tlsCert, tlsKey)
		} else {
			log.Printf("kosiro agent listening on %s (no TLS — set KOSIRO_TLS_CERT / KOSIRO_TLS_KEY)", addr)
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func bootstrapDefaultXray(store *db.Store, dataDir string) error {
	protos, err := store.ListProtocols()
	if err != nil {
		return err
	}
	users, err := store.ListUsers()
	if err != nil {
		return err
	}
	host := getenv("KOSIRO_PUBLIC_HOST", "127.0.0.1")
	cfg, err := xray.BuildConfig(host, protos, users, "0.0.0.0:10085", "warning")
	if err != nil {
		return err
	}
	return xray.WriteConfigFile(dataDir, cfg)
}
