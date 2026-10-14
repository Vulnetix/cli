package main

import (
	"context"
	"database/sql"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.com/shop/internal/audit"
	"example.com/shop/internal/auth"
	"example.com/shop/internal/cache"
	"example.com/shop/internal/config"
	"example.com/shop/internal/metrics"
	"example.com/shop/internal/orders"
	"example.com/shop/internal/payments"
)

~>func main() {
	cfgPath := flag.String("config", "config.yaml", "path to the config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		logger.Error("open database", "err", err)
		os.Exit(1)
	}
	db.SetMaxOpenConns(cfg.MaxConns)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err := db.PingContext(context.Background()); err != nil {
		logger.Error("ping database", "err", err)
		os.Exit(1)
	}

	store := cache.NewRedis(cfg.RedisAddr)
	defer store.Close()
	reg := metrics.NewRegistry()
	metrics.RegisterRuntime(reg)

	verifier, err := auth.NewVerifier(cfg.JWKSURL)
	if err != nil {
		logger.Error("auth verifier", "err", err)
		os.Exit(1)
	}
	auditLog := audit.Open(cfg.AuditPath)
	gateway := payments.NewGateway(cfg.PaymentsKey, payments.WithTimeout(10*time.Second))
	svc := orders.NewService(db, store, gateway, auditLog)

	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler(reg))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/orders", auth.Require(verifier, orders.ListHandler(svc)))
	mux.Handle("/orders/new", auth.Require(verifier, orders.CreateHandler(svc)))
	mux.Handle("/refunds", auth.RequireRole(verifier, "admin", payments.RefundHandler(gateway)))

	handler := metrics.Instrument(reg, audit.Middleware(auditLog, mux))
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("listening", "addr", cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("serve", "err", err)
			stop()
		}
	}()

	go svc.StartReconciler(ctx, time.Minute)
	go gateway.StartWebhookPoller(ctx)
	go store.StartJanitor(ctx)

	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		logger.Warn("shutdown", "err", err)
	}
	auditLog.Flush()
	reg.Unregister(metrics.RuntimeCollector())
	if err := db.Close(); err != nil {
		logger.Warn("close database", "err", err)
	}
	logger.Info("stopped", "uptime", time.Since(cfg.StartedAt).String())
}
