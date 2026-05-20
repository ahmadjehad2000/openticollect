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
