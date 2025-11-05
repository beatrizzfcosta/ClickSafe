PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

/* ======================================
   1) Resultado agregado da análise
   ====================================== */
CREATE TABLE IF NOT EXISTS analyses (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  url           TEXT    NOT NULL,
  normalized_url TEXT   NOT NULL,                 -- ex.: sem trailing slash, lower em host
  score         REAL    NOT NULL                  -- 0..100 (agregado)
                  CHECK (score >= 0 AND score <= 100),
  explanation   TEXT    NOT NULL,                 -- texto (IA explicativa)
  created_at    DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_analyses_normalized_url ON analyses (normalized_url);
CREATE INDEX IF NOT EXISTS idx_analyses_created_at     ON analyses (created_at);


/* ======================================
   2) Fontes de reputação por análise
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
   3) (Opcional) Heurísticas por análise
   ====================================== */
CREATE TABLE IF NOT EXISTS heuristics_hits (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id   INTEGER NOT NULL
                  REFERENCES analyses(id) ON DELETE CASCADE,

  type          TEXT    NOT NULL CHECK (type IN (
                  'DOMAIN_AGE',
                  'DOMAIN_EXPIRATION',
                  'DOMAIN_TLD_RISK',
                  'DOMAIN_IS_IP_ADDRESS',
                  'DOMAIN_SIMILAR_TO_BRAND',
                  'DOMAIN_SENSITIVE_KEYWORDS',
                  'DOMAIN_MULTIPLE_SUBLEVELS',
                  'DOMAIN_HYPHENS_USAGE',
                  'DOMAIN_HAS_HTTPS',
                  'DOMAIN_SSL_INVALID',
                  'DOMAIN_DNS_ANOMALY',
                  'DOMAIN_REVERSE_LOOKUP_FAIL',
                  'DOMAIN_GEOLOCATION_RISK',
                  'PATH_LENGTH_EXCESSIVE',
                  'PATH_COMPLEXITY_HIGH',
                  'PATH_ADMIN_DIRECTORIES',
                  'PATH_FAKE_FILENAME',
                  'PATH_DOUBLE_EXTENSION',
                  'PATH_EXECUTABLE_DISGUISED',
                  'PATH_SOCIAL_ENGINEERING_TERMS',
                  'PARAMS_EXCESSIVE_NUMBER',
                  'PARAMS_SENSITIVE_VARIABLES',
                  'PARAMS_LONG_OR_ENCODED_VALUES',
                  'PARAMS_REDIRECT_KEYWORD',
                  'PARAMS_PERSONAL_DATA_INCLUDED',
                  'SHORTENER_USAGE',
                  'MULTIPLE_REDIRECTS',
                  'EMBEDDED_PROTOCOLS',
                  'LANGUAGE_MIX',
                  'EMOJI_OR_SYMBOL_USAGE',
                  'ATTRACTIVE_PHRASES',
                  'KEYWORD_REPETITION',
                  'BRAND_IMPERSONATION'
                )),

  severity      TEXT    NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  status        TEXT    NOT NULL CHECK (status IN ('TRUE','FALSE')),   -- heurística foi acionada?
  details       TEXT,                                                   -- valores calculados, exemplos, etc.
  created_at    DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_heuristics_hits_analysis ON heuristics_hits (analysis_id);
CREATE INDEX IF NOT EXISTS idx_heuristics_hits_type     ON heuristics_hits (type);
