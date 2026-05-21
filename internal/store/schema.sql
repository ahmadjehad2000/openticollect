CREATE TABLE IF NOT EXISTS keywords (
  id INTEGER PRIMARY KEY,
  value TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('literal','regex')),
  severity TEXT NOT NULL CHECK (severity IN ('info','warn','critical')) DEFAULT 'warn',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(value, kind)
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  source_url TEXT,
  matched_keyword TEXT NOT NULL,
  severity TEXT NOT NULL,
  excerpt TEXT NOT NULL,
  raw TEXT,
  hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new',
  notified_at DATETIME,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(hash)
);
CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_source  ON findings(source);
CREATE INDEX IF NOT EXISTS idx_findings_status  ON findings(status);

CREATE TABLE IF NOT EXISTS source_runs (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  started_at DATETIME NOT NULL,
  finished_at DATETIME,
  ok INTEGER NOT NULL DEFAULT 0,
  items_fetched INTEGER NOT NULL DEFAULT 0,
  findings_created INTEGER NOT NULL DEFAULT 0,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_source_runs_source_time ON source_runs(source, started_at DESC);

CREATE TABLE IF NOT EXISTS source_state (
  source TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS correlation_rules (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  keyword TEXT NOT NULL DEFAULT '',
  min_sources INTEGER NOT NULL DEFAULT 2,
  min_count INTEGER NOT NULL DEFAULT 1,
  window_minutes INTEGER NOT NULL DEFAULT 1440,
  severity TEXT NOT NULL CHECK (severity IN ('info','warn','critical')) DEFAULT 'warn',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS indicators (
  id INTEGER PRIMARY KEY,
  finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(finding_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_indicators_finding ON indicators(finding_id);
CREATE INDEX IF NOT EXISTS idx_indicators_value   ON indicators(value);
CREATE INDEX IF NOT EXISTS idx_indicators_kind    ON indicators(kind);
