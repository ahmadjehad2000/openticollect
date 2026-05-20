// Package server renders the embedded web UI and handles HTTP requests.
package server

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"openticollect/internal/collectors"
	"openticollect/internal/config"
	"openticollect/internal/store"
	"openticollect/web"
)

// NextRunner reports a collector's next scheduled run; *scheduler.Scheduler
// satisfies it. Kept minimal so handlers are testable without a live scheduler.
type NextRunner interface {
	NextRun(name string) (time.Time, bool)
}

type Server struct {
	cfg      *config.Config
	store    *store.Store
	sched    NextRunner
	cols     []collectors.Collector
	log      *slog.Logger
	pages    map[string]*template.Template
	partials *template.Template
	mux      http.Handler
}

// pageData is the value passed to every full-page template.
type pageData struct {
	Title       string
	Heading     string
	Description string
	Nav         string // active nav item id
	Auth        bool   // basic auth configured
	Data        any
}

// New builds a Server, parsing all templates up front.
func New(cfg *config.Config, st *store.Store, sched NextRunner,
	cols []collectors.Collector, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{cfg: cfg, store: st, sched: sched, cols: cols, log: log}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) parseTemplates() error {
	funcs := s.funcMap()
	pages := map[string]*template.Template{}
	for _, name := range []string{"dashboard", "findings", "sources", "keywords", "settings"} {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(web.Templates,
			"templates/layout.html", "templates/partials/*.html", "templates/"+name+".html")
		if err != nil {
			return fmt.Errorf("server: parse %s page: %w", name, err)
		}
		pages[name] = t
	}
	partials, err := template.New("partials").Funcs(funcs).ParseFS(web.Templates,
		"templates/partials/*.html")
	if err != nil {
		return fmt.Errorf("server: parse partials: %w", err)
	}
	s.pages = pages
	s.partials = partials
	return nil
}

func (s *Server) funcMap() template.FuncMap {
	return template.FuncMap{
		"icon":       icon,
		"truncate":   truncate,
		"sevClass":   sevClass,
		"fmtTime":    fmtTime,
		"fmtTimePtr": fmtTimePtr,
		"mask":       config.Mask,
	}
}

// render writes a full page (layout + content) via a buffer so a mid-render
// error never produces a partially-written response.
func (s *Server) render(w http.ResponseWriter, page string, d pageData) {
	d.Auth = s.cfg.BasicAuthUser != "" && s.cfg.BasicAuthPass != ""
	tmpl, ok := s.pages[page]
	if !ok {
		s.log.Error("server: unknown page", "page", page)
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout.html", d); err != nil {
		s.log.Error("server: render failed", "page", page, "err", err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.Copy(w, &buf)
}

// renderPartial writes a single named partial, for HTMX fragment responses.
func (s *Server) renderPartial(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := s.partials.ExecuteTemplate(&buf, name, data); err != nil {
		s.log.Error("server: render partial failed", "name", name, "err", err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.Copy(w, &buf)
}

// routes is replaced with the full route table in P3 Task 4.
func (s *Server) routes() {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(web.Static))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	s.mux = mux
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func sevClass(severity string) string { return "badge-" + severity }

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04")
}

func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return fmtTime(*t)
}
