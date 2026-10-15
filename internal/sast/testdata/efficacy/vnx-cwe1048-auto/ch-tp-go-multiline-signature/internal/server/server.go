package server

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"example.com/billing/internal/auth"
	"example.com/billing/internal/invoices"
	"example.com/billing/internal/ledger"
	"example.com/billing/internal/mailer"
)

type Server struct {
	db  *sql.DB
	mux *http.ServeMux
	log *slog.Logger
}

~>func New(
	ctx context.Context,
	dsn string,
	logger *slog.Logger,
) (*Server, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetConnMaxLifetime(time.Minute)
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}
	certFile := os.Getenv("TLS_CERT")
	keyFile := os.Getenv("TLS_KEY")
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		logger.Warn("tls disabled", "err", err)
	}
	signer, err := auth.NewSigner(os.Getenv("JWT_KEY"))
	if err != nil {
		return nil, err
	}
	verifier := auth.NewVerifier(signer.PublicKey())
	repo := invoices.NewRepository(db)
	book := ledger.Open(db)
	if err := book.Migrate(ctx); err != nil {
		return nil, err
	}
	smtp := mailer.Dial(os.Getenv("SMTP_ADDR"))
	defer smtp.Flush()
	mux := http.NewServeMux()
	mux.Handle("/invoices", verifier.Require(invoices.ListHandler(repo)))
	mux.Handle("/invoices/new", verifier.Require(invoices.CreateHandler(repo, book)))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web"))))
	name := strings.TrimSpace(os.Getenv("SERVICE_NAME"))
	host, _ := os.Hostname()
	logger = logger.With("service", strings.ToLower(name), "host", host)
	logger.Info("server ready", "certs", len(pair.Certificate))
	ledger.RegisterMetrics(book)
	invoices.StartReminder(ctx, repo, smtp)
	mailer.SetDefaultSender(fmt.Sprintf("billing@%s", host))
	auth.ScheduleRotation(ctx, signer)
	go book.Compact(ctx)
	timeout := time.Duration(30) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := repo.Warm(ctx); err != nil {
		logger.Error("warm cache", "err", err)
	}
	slog.SetDefault(logger)
	return &Server{db: db, mux: mux, log: logger}, nil
}

func (s *Server) Close() error {
	return s.db.Close()
}
