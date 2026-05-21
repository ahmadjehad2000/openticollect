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
	"openticollect/internal/logbuf"
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

	st, err := store.Open(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer st.Close()

	// Overlay settings persisted via the Settings page on top of the
	// environment, then reload so the merged config is authoritative.
	if overrides, err := st.AllSettings(); err == nil && len(overrides) > 0 {
		for k, v := range overrides {
			if k == "DATABASE_PATH" || k == "LISTEN_ADDR" {
				continue
			}
			os.Setenv(k, v)
		}
		if reloaded, rerr := config.Load(); rerr == nil {
			cfg = reloaded
		} else {
			slog.Warn("settings overrides invalid; using environment config", "err", rerr)
		}
	}

	logs := logbuf.New(500)
	log := slog.New(logs.Handler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel(cfg.LogLevel),
	})))
	slog.SetDefault(log)
	log.Info("starting openTIcollect", "version", version.Version, "addr", cfg.ListenAddr)

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

	srv, err := server.New(cfg, st, sched, allCols, log, logs)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go sched.Run(ctx)

	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: srv}

	// A settings save persists overrides to the DB then calls this to
	// re-exec the binary so the new configuration is applied cleanly.
	srv.SetRestart(func() {
		time.Sleep(700 * time.Millisecond) // let the HTTP response flush
		log.Info("restarting to apply settings")
		shutCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		_ = httpSrv.Shutdown(shutCtx)
		cancel()
		_ = st.Close()
		exe, err := os.Executable()
		if err != nil {
			log.Error("restart: cannot resolve executable", "err", err)
			os.Exit(1)
		}
		if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
			log.Error("restart: exec failed", "err", err)
			os.Exit(1)
		}
	})
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
