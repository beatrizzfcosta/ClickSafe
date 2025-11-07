PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

/* ======================================
   1) Tabela de Links (URLs normalizadas)
   ====================================== */
CREATE TABLE IF NOT EXISTS links (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  url             TEXT    NOT NULL,                 -- URL original
  url_normalized  TEXT    NOT NULL,                 -- URL normalizada (sem trailing slash, lower em host)
  hostname        TEXT    NOT NULL,                 -- Hostname extraído para consultas rápidas
  created_at      DATETIME NOT NULL DEFAULT (datetime('now')),
  
  UNIQUE (url_normalized)
);

CREATE INDEX IF NOT EXISTS idx_links_url_normalized ON links (url_normalized);
CREATE INDEX IF NOT EXISTS idx_links_hostname       ON links (hostname);
CREATE INDEX IF NOT EXISTS idx_links_created_at     ON links (created_at);


/* ======================================
   2) Resultado agregado da análise
   ====================================== */
CREATE TABLE IF NOT EXISTS analyses (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  link_id         INTEGER NOT NULL
                    REFERENCES links(id) ON DELETE CASCADE,
  score           REAL    NOT NULL                  -- 0..100 (agregado)
                    CHECK (score >= 0 AND score <= 100),
  explanation     TEXT    NOT NULL,                 -- texto (IA explicativa)
  created_at      DATETIME NOT NULL DEFAULT (datetime('now')),
  last_analyzed_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_analyses_link_id         ON analyses (link_id);
CREATE INDEX IF NOT EXISTS idx_analyses_created_at      ON analyses (created_at);
CREATE INDEX IF NOT EXISTS idx_analyses_last_analyzed   ON analyses (last_analyzed_at);


/* ======================================
   3) Fontes de reputação por análise
   ====================================== */
CREATE TABLE IF NOT EXISTS reputation_checks (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id   INTEGER NOT NULL
                  REFERENCES analyses(id) ON DELETE CASCADE,

  source        TEXT    NOT NULL
                  CHECK (source IN ('VIRUSTOTAL','PHISHTANK','GOOGLE_SAFE_BROWSING')),

  status        TEXT    NOT NULL
                  CHECK (status IN ('POSITIVE','NEGATIVE')),
  /* Convenção:
     - POSITIVE  = a fonte sinalizou risco/malicioso
     - NEGATIVE  = a fonte não encontrou problema (limpo)
     (indisponibilidade/timeout serão sinalizadas em "reason" e não mudam status) */

  reason        TEXT,                              -- ex.: 'timeout', 'no_key', 'rate_limit', 'ok'
  raw_json      TEXT    NOT NULL,                  -- resposta integral da API (para auditoria)
  elapsed_ms    INTEGER,                           -- latência daquela consulta
  checked_at    DATETIME NOT NULL DEFAULT (datetime('now')),

  UNIQUE (analysis_id, source)
);

CREATE INDEX IF NOT EXISTS idx_reputation_checks_analysis ON reputation_checks (analysis_id);
CREATE INDEX IF NOT EXISTS idx_reputation_checks_source   ON reputation_checks (source);


/* ======================================
   4) Tabela de referência de Heurísticas
   ====================================== */
CREATE TABLE IF NOT EXISTS heuristics (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  code              TEXT    NOT NULL UNIQUE,       -- ex.: 'DOMAIN_AGE', 'PATH_LENGTH_EXCESSIVE'
  name              TEXT    NOT NULL,               -- nome legível
  category          TEXT    NOT NULL,               -- ex.: 'DOMAIN', 'PATH', 'PARAMS', 'GENERAL'
  description       TEXT    NOT NULL,               -- descrição da heurística
  default_severity  TEXT    NOT NULL                -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
                    CHECK (default_severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  default_weight    REAL    NOT NULL                -- peso padrão para cálculo de score
                    CHECK (default_weight >= 0 AND default_weight <= 1)
);

CREATE INDEX IF NOT EXISTS idx_heuristics_code     ON heuristics (code);
CREATE INDEX IF NOT EXISTS idx_heuristics_category ON heuristics (category);


/* ======================================
   5) Heurísticas acionadas por análise
   ====================================== */
CREATE TABLE IF NOT EXISTS heuristics_hits (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id   INTEGER NOT NULL
                  REFERENCES analyses(id) ON DELETE CASCADE,
  heuristic_id  INTEGER NOT NULL
                  REFERENCES heuristics(id) ON DELETE CASCADE,

  severity      TEXT    NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  triggered     INTEGER NOT NULL DEFAULT 0         -- 0 = não acionada, 1 = acionada
                    CHECK (triggered IN (0, 1)),
  details       TEXT,                               -- valores calculados, exemplos, etc.
  created_at    DATETIME NOT NULL DEFAULT (datetime('now')),

  UNIQUE (analysis_id, heuristic_id)
);

CREATE INDEX IF NOT EXISTS idx_heuristics_hits_analysis    ON heuristics_hits (analysis_id);
CREATE INDEX IF NOT EXISTS idx_heuristics_hits_heuristic    ON heuristics_hits (heuristic_id);
CREATE INDEX IF NOT EXISTS idx_heuristics_hits_triggered    ON heuristics_hits (triggered);


/* ======================================
   6) Requisições de IA por análise
   ====================================== */
CREATE TABLE IF NOT EXISTS ai_requests (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id   INTEGER NOT NULL
                  REFERENCES analyses(id) ON DELETE CASCADE,

  model         TEXT    NOT NULL,                   -- ex.: 'gpt-4', 'claude-3', etc.
  prompt        TEXT    NOT NULL,                   -- prompt enviado à IA
  response      TEXT    NOT NULL,                   -- resposta da IA
  risk_score    REAL,                               -- score de risco calculado pela IA (0..100)
  meta          TEXT,                               -- metadados adicionais (JSON)
  created_at    DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ai_requests_analysis ON ai_requests (analysis_id);
CREATE INDEX IF NOT EXISTS idx_ai_requests_model    ON ai_requests (model);
CREATE INDEX IF NOT EXISTS idx_ai_requests_created  ON ai_requests (created_at);
