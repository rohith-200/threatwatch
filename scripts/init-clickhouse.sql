-- ThreatWatch ClickHouse schema.
-- The backend creates these automatically at startup (src/store/clickhouse.ts).
-- This file is the same schema, for reference or manual setup.

CREATE DATABASE IF NOT EXISTS threatwatch;

-- One row per analysis. report_json holds the full Report so the UI loads it in one lookup.
CREATE TABLE IF NOT EXISTS threatwatch.analyses
(
    analysis_id         String,
    repo                String,
    commit              String,
    analyzed_at         DateTime64(3, 'UTC'),
    lookback_days       UInt16,
    dependencies        UInt32,
    direct_dependencies UInt32,
    advisories_checked  UInt32,
    kev_checked         UInt32,
    alerts              UInt16,
    likely              UInt16,
    new_affecting       UInt16,
    total_risk          UInt32,
    from_cache          Bool,
    report_json         String
)
ENGINE = MergeTree
ORDER BY (repo, analyzed_at);

-- One row per alert per analysis. Used for history, trends and "new since last analysis".
CREATE TABLE IF NOT EXISTS threatwatch.findings
(
    analysis_id       String,
    repo              String,
    analyzed_at       DateTime64(3, 'UTC'),
    canonical_id      String,
    aliases           Array(String),
    package           LowCardinality(String),
    installed_version String,
    fixed_version     Nullable(String),
    severity          LowCardinality(String),
    status            LowCardinality(String),
    risk_score        UInt8,
    is_new            Bool,
    in_kev            Bool,
    epss              Nullable(Float32),
    evidence_count    UInt16,
    simulated         Bool,
    evidence_check    LowCardinality(String)
)
ENGINE = MergeTree
ORDER BY (repo, analyzed_at, canonical_id);