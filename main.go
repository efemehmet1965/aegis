package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aegis-phishing/config"
	"aegis-phishing/internal/ai"
	"aegis-phishing/internal/analyzer"
	"aegis-phishing/internal/fetcher"
	"aegis-phishing/internal/handler"
	"aegis-phishing/internal/parser"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	cfg := config.Load()

	var logLevel slog.Level
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	slog.Info("starting aegis",
		"port", cfg.Port,
		"model", cfg.DeepSeekModel,
		"log_level", cfg.LogLevel,
	)

	// Initialize dependencies
	fetcherSvc := fetcher.NewFetcher(cfg)
	reverseIP := fetcher.NewReverseIPFetcher(cfg)
	whoisSvc := fetcher.NewWhoisFetcher(cfg)
	htmlParser := parser.NewParser()
	preAnalyzer := analyzer.NewPreAnalyzer()
	deepseekAI := ai.NewDeepSeek(cfg)

	// Router setup
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(120 * time.Second))

	// CORS
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// Handlers
	checkHandler := handler.NewCheckHandler(fetcherSvc, whoisSvc, htmlParser, preAnalyzer, deepseekAI)
	sweepHandler := handler.NewSweepHandler(cfg, fetcherSvc, reverseIP, whoisSvc, htmlParser, preAnalyzer, deepseekAI)
	healthHandler := handler.NewHealthHandler()

	// Routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", healthHandler.Handle)
		r.Post("/check", checkHandler.Handle)
		r.Post("/sweep", sweepHandler.StartSweep)
		r.Get("/sweep/{taskID}", sweepHandler.GetTaskStatus)
	})

	// HTTP server
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	sig := <-quit
	slog.Info("shutdown signal received", "signal", sig.String())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
		os.Exit(1)
	}

	fmt.Println("\nAegis shut down gracefully.")
}
