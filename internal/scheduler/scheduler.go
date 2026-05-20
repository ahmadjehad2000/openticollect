// Package scheduler runs each collector on its own goroutine with jitter and
// exponential backoff, persisting every run and dispatching new findings.
package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"openticollect/internal/collectors"
	"openticollect/internal/config"
	"openticollect/internal/models"
	"openticollect/internal/notifier"
	"openticollect/internal/store"
)

const (
	runTimeout   = 2 * time.Minute
	startupDelay = 3 * time.Second
	backoffCap   = 30 * time.Minute
)

type Scheduler struct {
	cfg        *config.Config
	store      *store.Store
	notifier   *notifier.Notifier
	collectors []collectors.Collector
	http       *http.Client
	tor        *http.Client
	log        *slog.Logger

	mu      sync.Mutex
	nextRun map[string]time.Time
}

func New(cfg *config.Config, st *store.Store, n *notifier.Notifier,
	cols []collectors.Collector, httpClient, tor *http.Client, log *slog.Logger) *Scheduler {
	if log == nil {
		log = slog.Default()
	}
	return &Scheduler{
		cfg: cfg, store: st, notifier: n, collectors: cols,
		http: httpClient, tor: tor, log: log,
		nextRun: make(map[string]time.Time),
	}
}

// Run starts one goroutine per collector and blocks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, c := range s.collectors {
		wg.Add(1)
		go func(c collectors.Collector) {
			defer wg.Done()
			s.loop(ctx, c)
		}(c)
	}
	wg.Wait()
}

// NextRun reports the next scheduled run for a collector, for the /sources page.
func (s *Scheduler) NextRun(name string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.nextRun[name]
	return t, ok
}

func (s *Scheduler) setNextRun(name string, t time.Time) {
	s.mu.Lock()
	s.nextRun[name] = t
	s.mu.Unlock()
}

func (s *Scheduler) loop(ctx context.Context, c collectors.Collector) {
	if !sleep(ctx, jitter(startupDelay)) {
		return
	}
	failures := 0
	for {
		if err := s.runCollector(ctx, c); err != nil {
			failures++
		} else {
			failures = 0
		}
		wait := jitter(c.Interval())
		if failures > 0 {
			wait = backoffDuration(failures, c.Interval(), backoffCap)
		}
		s.setNextRun(c.Name(), time.Now().Add(wait))
		if !sleep(ctx, wait) {
			return
		}
	}
}

// runCollector runs one collector once: it records the run and dispatches new
// findings. It returns the collector's error (nil on success) for backoff logic.
func (s *Scheduler) runCollector(ctx context.Context, c collectors.Collector) error {
	enabled, err := s.store.SourceEnabled(c.Name())
	if err != nil {
		s.log.Error("scheduler: source state lookup failed", "collector", c.Name(), "err", err)
		return err
	}
	if !enabled {
		return nil
	}

	keywords, err := s.store.EnabledKeywords()
	if err != nil {
		s.log.Error("scheduler: load keywords failed", "collector", c.Name(), "err", err)
		return err
	}

	runCtx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	in := collectors.Input{
		Keywords: keywords, HTTP: s.http, Tor: s.tor,
		Logger: s.log.With("collector", c.Name()),
	}

	started := time.Now()
	res, runErr := safeRun(c, runCtx, in)
	finished := time.Now()

	var inserted []models.Finding
	if runErr == nil {
		inserted, err = s.store.InsertFindings(res.Findings)
		if err != nil {
			runErr = err
		}
	}

	errStr := ""
	if runErr != nil {
		errStr = runErr.Error()
		s.log.Warn("scheduler: collector run failed", "collector", c.Name(), "err", runErr)
	}
	if recErr := s.store.RecordRun(c.Name(), started, finished, runErr == nil,
		res.ItemsFetched, len(inserted), errStr); recErr != nil {
		s.log.Error("scheduler: record run failed", "collector", c.Name(), "err", recErr)
	}

	if len(inserted) > 0 {
		s.notifier.Dispatch(ctx, inserted)
		now := time.Now()
		for _, f := range inserted {
			if err := s.store.MarkNotified(f.ID, now); err != nil {
				s.log.Error("scheduler: mark notified failed", "finding", f.ID, "err", err)
			}
		}
	}
	return runErr
}

// safeRun calls c.Run and converts a panic into an error.
func safeRun(c collectors.Collector, runCtx context.Context,
	in collectors.Input) (res collectors.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("collector %s panicked: %v", c.Name(), r)
		}
	}()
	return c.Run(runCtx, in)
}

// jitter returns d adjusted by a random +/-10%.
func jitter(d time.Duration) time.Duration {
	factor := 0.9 + rand.Float64()*0.2
	return time.Duration(float64(d) * factor)
}

// backoffDuration is base * 2^attempt, capped.
func backoffDuration(attempt int, base, cap time.Duration) time.Duration {
	d := time.Duration(float64(base) * math.Pow(2, float64(attempt)))
	if d > cap || d <= 0 {
		return cap
	}
	return d
}

// sleep waits for d or ctx cancellation; it returns false if ctx was cancelled.
func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
