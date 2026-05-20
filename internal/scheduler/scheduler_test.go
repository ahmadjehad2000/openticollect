package scheduler

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"openticollect/internal/collectors"
	"openticollect/internal/config"
	"openticollect/internal/models"
	"openticollect/internal/notifier"
	"openticollect/internal/store"
)

// fakeCollector is a Collector whose behavior the test controls.
type fakeCollector struct {
	name     string
	findings []models.Finding
	err      error
	panic    bool
}

func (f *fakeCollector) Name() string                      { return f.name }
func (f *fakeCollector) Enabled(*config.Config) bool        { return true }
func (f *fakeCollector) MissingEnv(*config.Config) []string { return nil }
func (f *fakeCollector) Interval() time.Duration            { return time.Hour }
func (f *fakeCollector) Run(context.Context, collectors.Input) (collectors.Result, error) {
	if f.panic {
		panic("boom")
	}
	return collectors.Result{ItemsFetched: len(f.findings), Findings: f.findings}, f.err
}

func newSched(t *testing.T, c collectors.Collector, sink notifier.Sink) (*Scheduler, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := &config.Config{}
	var n *notifier.Notifier
	if sink != nil {
		n = notifier.New(nil, sink)
	} else {
		n = notifier.New(nil)
	}
	s := New(cfg, st, n, []collectors.Collector{c}, collectors.DefaultHTTPClient(), nil, nil)
	return s, st
}

func TestRunCollectorInsertsFindingsAndRecordsRun(t *testing.T) {
	f := models.Finding{Source: "fake", SourceURL: "u", MatchedKeyword: "k",
		Severity: "critical", Excerpt: "e", Hash: models.HashFinding("fake", "u", "k")}
	fc := &fakeCollector{name: "fake", findings: []models.Finding{f}}
	s, st := newSched(t, fc, nil)

	if err := s.runCollector(context.Background(), fc); err != nil {
		t.Fatalf("runCollector: %v", err)
	}
	_, total, _ := st.ListFindings(store.FindingFilter{Limit: 50})
	if total != 1 {
		t.Fatalf("expected 1 finding stored, got %d", total)
	}
	run, _ := st.LatestRun("fake")
	if run == nil || !run.OK || run.FindingsCreated != 1 {
		t.Fatalf("run not recorded correctly: %#v", run)
	}
}

func TestRunCollectorRecordsFailure(t *testing.T) {
	fc := &fakeCollector{name: "fake", err: errors.New("upstream 500")}
	s, st := newSched(t, fc, nil)

	if err := s.runCollector(context.Background(), fc); err == nil {
		t.Fatal("expected error from failing collector")
	}
	run, _ := st.LatestRun("fake")
	if run == nil || run.OK || run.Error == "" {
		t.Fatalf("failed run not recorded: %#v", run)
	}
}

func TestRunCollectorRecoversPanic(t *testing.T) {
	fc := &fakeCollector{name: "fake", panic: true}
	s, st := newSched(t, fc, nil)

	if err := s.runCollector(context.Background(), fc); err == nil {
		t.Fatal("panic should surface as an error, not crash")
	}
	run, _ := st.LatestRun("fake")
	if run == nil || run.OK {
		t.Fatalf("panicking run should be recorded as failed: %#v", run)
	}
}

func TestRunCollectorSkipsDisabledSource(t *testing.T) {
	f := models.Finding{Source: "fake", Hash: "h", MatchedKeyword: "k", Severity: "warn", Excerpt: "e"}
	fc := &fakeCollector{name: "fake", findings: []models.Finding{f}}
	s, st := newSched(t, fc, nil)
	if err := st.SetSourceEnabled("fake", false); err != nil {
		t.Fatal(err)
	}
	if err := s.runCollector(context.Background(), fc); err != nil {
		t.Fatalf("disabled collector run should be a no-op, got %v", err)
	}
	if _, total, _ := st.ListFindings(store.FindingFilter{Limit: 50}); total != 0 {
		t.Fatalf("disabled collector must not produce findings, got %d", total)
	}
}

func TestJitterWithinBounds(t *testing.T) {
	base := time.Hour
	for i := 0; i < 200; i++ {
		j := jitter(base)
		if j < time.Duration(float64(base)*0.9) || j > time.Duration(float64(base)*1.1) {
			t.Fatalf("jitter %v outside +/-10%% of %v", j, base)
		}
	}
}

func TestBackoffCaps(t *testing.T) {
	base := time.Minute
	cap := 30 * time.Minute
	if d := backoffDuration(1, base, cap); d != 2*time.Minute {
		t.Fatalf("backoff(1) = %v, want 2m", d)
	}
	if d := backoffDuration(20, base, cap); d != cap {
		t.Fatalf("backoff(20) = %v, want cap %v", d, cap)
	}
}
