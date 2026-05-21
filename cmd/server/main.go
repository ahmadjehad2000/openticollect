// Command server is the openTIcollect entrypoint: it wires config, store,
// collectors, scheduler, notifier, and the web server, with graceful shutdown.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"openticollect/internal/collectors"
	"openticollect/internal/config"
	"openticollect/internal/correlation"
	"openticollect/internal/notifier"
	"openticollect/internal/scheduler"
	"openticollect/internal/server"
	"openticollect/internal/store"
	"openticollect/internal/version"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel(cfg.LogLevel),
	}))
	slog.SetDefault(log)
	log.Info("starting openTIcollect", "version", version.Version, "addr", cfg.ListenAddr)

	st, err := store.Open(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer st.Close()

	var sinks []notifier.Sink
	if wh := notifier.NewWebhookSink(cfg.WebhookURL, cfg.WebhookSecret,
		cfg.WebhookMinSeverity, collectors.DefaultHTTPClient()); wh != nil {
		sinks = append(sinks, wh)
	}
	if em := notifier.NewEmailSink(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser,
		cfg.SMTPPass, cfg.SMTPFrom, cfg.SMTPTo, cfg.EmailMinSeverity); em != nil {
		sinks = append(sinks, em)
	}
	n := notifier.New(log, sinks...)

	allCols := collectors.All(cfg)
	var active []collectors.Collector
	for _, c := range allCols {
		if c.Enabled(cfg) {
			active = append(active, c)
		}
	}
	log.Info("collectors registered", "total", len(allCols), "active", len(active))

	var torClient *http.Client
	if cfg.TorProxy != "" {
		tc, err := collectors.TorClient(cfg.TorProxy)
		if err != nil {
			log.Warn("tor client unavailable; onion watchlist disabled", "err", err)
		} else {
			torClient = tc
			log.Info("tor client configured", "proxy", cfg.TorProxy)
		}
	}

	corr := correlation.NewRunner(st)
	sched := scheduler.New(cfg, st, n, active, corr,
		collectors.DefaultHTTPClient(), torClient, log)

	srv, err := server.New(cfg, st, sched, allCols, log)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go sched.Run(ctx)

	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: srv}
	go func() {
		log.Info("http server listening", "addr", cfg.ListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server error", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutCtx); err != nil {
		return fmt.Errorf("http shutdown: %w", err)
	}
	return nil
}

func logLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
